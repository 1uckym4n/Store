// ==UserScript==
// @name         Binance P2P QR Code Generator
// @namespace    http://tampermonkey.net/
// @version      2026-06-17-VietQR-API
// @description  Collect payment info (via Binance API capture) and generate VietQR code for Binance P2P orders
// @author       You
// @match        https://p2p.binance.com/vi/fiatOrderDetail?orderNo=*
// @match        https://c2c.binance.com/*
// @icon         https://www.google.com/s2/favicons?sz=64&domain=binance.com
// @run-at       document-start
// @grant        GM_xmlhttpRequest
// @grant        unsafeWindow
// ==/UserScript==
// Collect info giờ đọc thẳng JSON từ API của Binance thay vì XPath (bền hơn nhiều)
(function() {
    'use strict';

    // =========================================================================
    //  PHẦN 1: BẮT DỮ LIỆU TỪ API CỦA BINANCE (chạy ở document-start)
    //  Trang order-detail tự gọi API trả về JSON có đầy đủ thông tin thanh toán.
    //  Ta hook fetch + XHR để chộp lại JSON đó, không phụ thuộc vào giao diện DOM.
    // =========================================================================
    let latestOrderDetail = null;
    let guiReady = false;            // GUI đã mount xong chưa
    let lastProcessedOrderNo = null; // đơn đã tự fill gần nhất (tránh ghi đè khi Binance poll lại)

    function stripVN(s) {
        return String(s || '')
            .normalize('NFD').replace(/[̀-ͯ]/g, '')
            .replace(/đ/g, 'd').replace(/Đ/g, 'D');
    }

    // Phân loại 1 trường thanh toán dựa trên TÊN trường (cả VN lẫn EN)
    function classifyField(rawName) {
        const n = String(rawName || '').toLowerCase();
        if (/(số tài khoản|account ?(number|no\b|#)|card ?number|số thẻ|iban)/.test(n)) return 'account';
        if (/(account holder|cardholder|chủ tài khoản|tên chủ|họ và tên|họ tên|tên tài khoản|account name)/.test(n)) return 'name';
        if (/(ngân hàng|\bbank\b)/.test(n)) return 'bank';
        if (/(name|tên)/.test(n)) return 'name';
        return null;
    }

    // Số tiền fiat (VND) — ưu tiên totalPrice, KHÔNG dùng `amount` (đó là số lượng crypto).
    // totalPrice của Binance có dạng "150000.00000000" → phải parseFloat rồi làm tròn,
    // KHÔNG dùng replace(/[^\d]/g,'') (sẽ biến 150000.00000000 thành 15000000000000).
    function pickAmount(d) {
        const raw = d.totalPrice != null ? d.totalPrice
                  : d.fiatAmount != null ? d.fiatAmount
                  : d.payAmount  != null ? d.payAmount
                  : d.orderAmount != null ? d.orderAmount : '';
        const num = parseFloat(String(raw).replace(/,/g, ''));
        return isNaN(num) ? '' : String(Math.round(num));
    }

    // Gom mọi cặp {fieldName, fieldValue} trong cây JSON (dự phòng khi cấu trúc khác)
    function collectFields(obj, acc, depth) {
        if (!obj || typeof obj !== 'object' || depth > 6) return;
        if (Array.isArray(obj)) { obj.forEach(o => collectFields(o, acc, depth + 1)); return; }
        const fn = obj.fieldName != null ? obj.fieldName : obj.name;
        const fv = obj.fieldValue != null ? obj.fieldValue
                 : obj.value != null ? obj.value : obj.content;
        if (typeof fn === 'string' && typeof fv === 'string' && fv.trim()) {
            acc.push({ name: fn, value: fv.trim() });
        }
        for (const k in obj) {
            try { collectFields(obj[k], acc, depth + 1); } catch (e) {}
        }
    }

    function findPayMethods(d) {
        if (Array.isArray(d.payMethods)) return d.payMethods;
        if (Array.isArray(d.payMethodList)) return d.payMethodList;
        if (Array.isArray(d.sellerPayMethods)) return d.sellerPayMethods;
        return [];
    }

    // Trích xuất {name, bank, account, content, amount} từ JSON order-detail
    function extractPayInfo(d) {
        const out = { name: '', bank: '', account: '', content: '', amount: '' };
        if (!d || typeof d !== 'object') return out;

        out.amount = pickAmount(d);
        // Nội dung CK: Binance hiển thị sẵn ở `refMessage` (vd "TRAN DUY NAM chuyen tien 517184")
        out.content = String(d.refMessage || d.orderNumber || d.orderNo || d.tradeNo || '').trim();
        const sellerName = d.sellerName || d.sellerNickname || d.makerName || '';

        // 1) Thử theo từng phương thức thanh toán: lấy phương thức nào có số tài khoản
        const methods = findPayMethods(d);
        for (const m of methods) {
            const fields = Array.isArray(m.fields) ? m.fields : [];
            const got = { bank: '', account: '', name: '' };
            for (const f of fields) {
                const cat = classifyField(f.fieldName || f.name);
                const val = String(f.fieldValue != null ? f.fieldValue : (f.value || '')).trim();
                if (cat && val && !got[cat]) got[cat] = val;
            }
            if (got.account) {
                out.account = got.account;
                out.bank = got.bank || m.tradeMethodName || m.identifier || '';
                out.name = got.name || sellerName;
                break;
            }
        }

        // 2) Dự phòng: quét toàn bộ cây JSON nếu chưa lấy được số tài khoản
        if (!out.account) {
            const acc = [];
            collectFields(d, acc, 0);
            for (const f of acc) {
                const cat = classifyField(f.name);
                if (cat && !out[cat]) out[cat] = f.value;
            }
            if (!out.name) out.name = sellerName;
        }

        out.name = stripVN(out.name).trim().toUpperCase();
        return out;
    }

    function maybeCapture(url, text) {
        try {
            if (!/c2c|order/i.test(String(url || ''))) return;
            const j = JSON.parse(text);
            const d = (j && typeof j === 'object' && j.data) ? j.data : j;
            if (d && typeof d === 'object' && (d.payMethods || d.orderNumber || d.sellerName)) {
                latestOrderDetail = d;
                try { unsafeWindow.__vietqrOrder = d; } catch (e) {}
                console.log('[VietQR] Đã bắt được order detail:', d);
                if (guiReady) autoRun();   // GUI sẵn sàng → tự fill + tạo QR
            }
        } catch (e) { /* không phải JSON cần thiết → bỏ qua */ }
    }

    function hookTarget(win) {
        // Hook fetch
        try {
            const origFetch = win.fetch;
            if (typeof origFetch === 'function' && !origFetch.__vietqrHooked) {
                const wrapped = function(...a) {
                    const p = origFetch.apply(this, a);
                    try {
                        const url = (a[0] && a[0].url) ? a[0].url : String(a[0] || '');
                        if (p && typeof p.then === 'function') {
                            p.then(function(r) {
                                try { r.clone().text().then(function(t) { maybeCapture(url, t); }).catch(function(){}); } catch (e) {}
                            }).catch(function(){});
                        }
                    } catch (e) {}
                    return p;
                };
                wrapped.__vietqrHooked = true;
                win.fetch = wrapped;
            }
        } catch (e) {}

        // Hook XMLHttpRequest
        try {
            const XHR = win.XMLHttpRequest;
            if (XHR && XHR.prototype && !XHR.prototype.__vietqrHooked) {
                const origOpen = XHR.prototype.open;
                const origSend = XHR.prototype.send;
                XHR.prototype.open = function(method, url) {
                    this.__vietqrUrl = url;
                    return origOpen.apply(this, arguments);
                };
                XHR.prototype.send = function() {
                    try {
                        this.addEventListener('load', function() {
                            try { maybeCapture(this.__vietqrUrl || '', this.responseText); } catch (e) {}
                        });
                    } catch (e) {}
                    return origSend.apply(this, arguments);
                };
                XHR.prototype.__vietqrHooked = true;
            }
        } catch (e) {}
    }

    // Hook cả unsafeWindow (page context) lẫn window (sandbox) để chắc ăn
    const hookTargets = [];
    try { if (typeof unsafeWindow !== 'undefined' && unsafeWindow) hookTargets.push(unsafeWindow); } catch (e) {}
    if (hookTargets.indexOf(window) === -1) hookTargets.push(window);
    hookTargets.forEach(hookTarget);

    // =========================================================================
    //  PHẦN 2: GIAO DIỆN + TẠO QR
    // =========================================================================
    const bankMapping = {
        // By short_name
        'VietinBank': '970415',
        'Vietcombank': '970436',
        'MBBank': '970422',
        'ACB': '970416',
        'VPBank': '970432',
        'TPBank': '970423',
        'MSB': '970426',
        'NamABank': '970428',
        'LienVietPostBank': '970449',
        'VietCapitalBank': '970454',
        'BIDV': '970418',
        'Sacombank': '970403',
        'VIB': '970441',
        'HDBank': '970437',
        'SeABank': '970440',
        'GPBank': '970408',
        'PVcomBank': '970412',
        'PVcomBankPay': '971133',
        'NCB': '970419',
        'ShinhanBank': '970424',
        'SCB': '970429',
        'PGBank': '970430',
        'Agribank': '970405',
        'Techcombank': '970407',
        'SaigonBank': '970400',
        'DongABank': '970406',
        'BacABank': '970409',
        'StandardChartered': '970410',
        'Oceanbank': '970414',
        'VRB': '970421',
        'ABBANK': '970425',
        'VietABank': '970427',
        'Eximbank': '970431',
        'VietBank': '970433',
        'IndovinaBank': '970434',
        'BaoVietBank': '970438',
        'PublicBank': '970439',
        'SHB': '970443',
        'CBBank': '970444',
        'OCB': '970448',
        'KienLongBank': '970452',
        'CIMB': '422589',
        'HSBC': '458761',
        'DBSBank': '796500',
        'Nonghyup': '801011',
        'HongLeong': '970442',
        'Woori': '970457',
        'UnitedOverseas': '970458',
        'KookminHN': '970462',
        'KookminHCM': '970463',
        'COOPBANK': '970446',

        // By code (alternative lookup)
        'ICB': '970415',
        'VCB': '970436',
        'MB': '970422',
        'VPB': '970432',
        'TPB': '970423',
        'NAB': '970428',
        'LPB': '970449',
        'VCCB': '970454',
        'STB': '970403',
        'HDB': '970437',
        'SEAB': '970440',
        'GPB': '970408',
        'PVCB': '970412',
        'PVCBP': '971133',
        'SHBVN': '970424',
        'VBA': '970405',
        'TCB': '970407',
        'SGICB': '970400',
        'DOB': '970406',
        'BAB': '970409',
        'SCVN': '970410',
        'ABB': '970425',
        'VAB': '970427',
        'EIB': '970431',
        'VIETBANK': '970433',
        'IVB': '970434',
        'BVB': '970438',
        'PBVN': '970439',
        'CBB': '970444',
        'KLB': '970452',
        'HLBVN': '970442',
        'WVN': '970457',
        'UOB': '970458',
        'KBHN': '970462',
        'KBHCM': '970463',

        // Common variations (case-insensitive handled by function)
        'vietcombank': '970436',
        'techcombank': '970407',
        'mb': '970422',
        'mbbank': '970422',
        'bidv': '970418',
        'agribank': '970405',
        'vpbank': '970432',
        'tpbank': '970423',
        'sacombank': '970403',
        'hdbank': '970437',
        'vib': '970441',
        'seabank': '970440',
        'acb': '970416',
        'ocb': '970448',
        'msb': '970426',
        'shb': '970443',
        'scb': '970429',
        'ncb': '970419',
        'eximbank': '970431',
        'lpb': '970449',
        'lienvietpostbank': '970449',
        'bacabank': '970409',
        'abbank': '970425',
        'vietinbank': '970415',
        'vietcapitalbank': '970454'
    };

    // Create main GUI container
    const container = document.createElement('div');
    container.style.cssText = `
        position: fixed;
        top: 10px;
        right: 10px;
        z-index: 9999;
        background-color: #1e1e1e;
        color: white;
        padding: 14px;
        border: 1px solid #444;
        border-radius: 10px;
        box-shadow: 0 0 20px rgba(0, 0, 0, 0.8);
        font-family: Arial, sans-serif;
        min-width: 300px;
        max-width: 340px;
        max-height: 95vh;
        overflow-y: auto;
        overflow-x: hidden;
    `;

    // Create title
    const title = document.createElement('h3');
    title.textContent = 'VietQR Generator';
    title.style.cssText = 'margin: 0 0 10px 0; color: #fcd535; text-align: center;';
    container.appendChild(title);

    // Create form fields
    const fields = [
        { label: 'Tên người nhận:', id: 'name', placeholder: 'Tên người nhận' },
        { label: 'Tên ngân hàng:', id: 'bank', placeholder: 'VD: Vietcombank, TCB' },
        { label: 'Số tài khoản:', id: 'account', placeholder: 'Số tài khoản' },
        { label: 'Nội dung CK:', id: 'content', placeholder: 'Mã giao dịch / Nội dung' },
        { label: 'Số tiền:', id: 'amount', placeholder: 'Số tiền (VND)' }
    ];

    const inputs = {};

    fields.forEach(field => {
        const fieldContainer = document.createElement('div');
        fieldContainer.style.cssText = 'margin-bottom: 8px;';

        const label = document.createElement('label');
        label.textContent = field.label;
        label.style.cssText = 'display: block; margin-bottom: 5px; font-size: 13px; color: #ccc;';
        fieldContainer.appendChild(label);

        const input = document.createElement('input');
        input.type = 'text';
        input.id = field.id;
        input.placeholder = field.placeholder;
        input.style.cssText = `
            width: 100%;
            padding: 8px;
            border: 1px solid #444;
            border-radius: 5px;
            background-color: #2d2d2d;
            color: white;
            font-size: 13px;
            box-sizing: border-box;
        `;
        fieldContainer.appendChild(input);
        container.appendChild(fieldContainer);
        inputs[field.id] = input;
    });

    // ⚡ Toggle: tự động tạo QR khi bắt được đơn mới (nhớ lựa chọn qua localStorage)
    const autoRow = document.createElement('label');
    autoRow.style.cssText = 'display:flex; align-items:center; gap:8px; margin:4px 0; font-size:13px; color:#ccc; cursor:pointer; user-select:none;';
    const autoChk = document.createElement('input');
    autoChk.type = 'checkbox';
    try { autoChk.checked = localStorage.getItem('vietqr_auto') !== '0'; } catch (e) { autoChk.checked = true; }
    autoChk.onchange = function() {
        try { localStorage.setItem('vietqr_auto', autoChk.checked ? '1' : '0'); } catch (e) {}
    };
    const autoTxt = document.createElement('span');
    autoTxt.textContent = '⚡ Tự động điền & tạo QR khi mở đơn';
    autoRow.appendChild(autoChk);
    autoRow.appendChild(autoTxt);
    container.appendChild(autoRow);

    function autoGenEnabled() { return autoChk.checked; }

    // Điền form từ dữ liệu order đã trích xuất
    function fillForm(info) {
        inputs.name.value = info.name || '';
        inputs.bank.value = info.bank || '';
        inputs.account.value = info.account || '';
        inputs.content.value = info.content || '';
        inputs.amount.value = info.amount || '';
    }

    // Tự động fill + (tùy chọn) tạo QR khi bắt được đơn MỚI.
    // Bỏ qua nếu vẫn là đơn đã xử lý (tránh ghi đè khi Binance poll lại trạng thái đơn).
    function autoRun() {
        if (!latestOrderDetail) return;
        const orderNo = String(latestOrderDetail.orderNumber || latestOrderDetail.orderNo || '');
        if (orderNo && orderNo === lastProcessedOrderNo) return;
        lastProcessedOrderNo = orderNo;
        try {
            fillForm(extractPayInfo(latestOrderDetail));
            if (autoGenEnabled()) generateQR(true);   // silent: không popup alert
        } catch (e) {
            console.error('[VietQR] autoRun lỗi:', e);
        }
    }

    // Create buttons container
    const buttonsContainer = document.createElement('div');
    buttonsContainer.style.cssText = 'display: flex; gap: 10px; margin-top: 15px;';

    // Collect button
    const collectBtn = document.createElement('button');
    collectBtn.textContent = '📥 Collect Thông Tin';
    collectBtn.style.cssText = `
        flex: 1;
        padding: 10px;
        background-color: #2196F3;
        color: white;
        border: none;
        border-radius: 5px;
        cursor: pointer;
        font-size: 13px;
        font-weight: bold;
        transition: background-color 0.3s;
    `;
    collectBtn.onmouseover = () => { collectBtn.style.backgroundColor = '#1976D2'; };
    collectBtn.onmouseout = () => { collectBtn.style.backgroundColor = '#2196F3'; };

    collectBtn.onclick = function() {
        try {
            if (!latestOrderDetail) {
                alert('⚠️ Chưa bắt được dữ liệu từ Binance.\nHãy F5 lại trang đơn hàng (script cần tải lại để chộp API), rồi bấm Collect lại.');
                return;
            }

            const info = extractPayInfo(latestOrderDetail);
            fillForm(info);

            alert(
                '✅ Đã collect từ API Binance!\n' +
                'Tên người nhận: ' + (info.name || 'N/A') + '\n' +
                'Ngân hàng: ' + (info.bank || 'N/A') + '\n' +
                'Số tài khoản: ' + (info.account || 'N/A') + '\n' +
                'Nội dung: ' + (info.content || 'N/A') + '\n' +
                'Số tiền: ' + (info.amount || 'N/A') + '\n\n' +
                '(Nếu thiếu trường nào, mở Console xem window.__vietqrOrder để báo lại)'
            );
        } catch (error) {
            console.error('[VietQR] Lỗi collect:', error);
            alert('❌ Lỗi khi collect thông tin. Vui lòng nhập thủ công.\n' + error);
        }
    };
    buttonsContainer.appendChild(collectBtn);

    // Generate QR button
    const generateBtn = document.createElement('button');
    generateBtn.textContent = '🎨 Tạo VietQR';
    generateBtn.style.cssText = `
        flex: 1;
        padding: 10px;
        background-color: #4CAF50;
        color: white;
        border: none;
        border-radius: 5px;
        cursor: pointer;
        font-size: 13px;
        font-weight: bold;
        transition: background-color 0.3s;
    `;
    generateBtn.onmouseover = () => { generateBtn.style.backgroundColor = '#45a049'; };
    generateBtn.onmouseout = () => { generateBtn.style.backgroundColor = '#4CAF50'; };

    // silent = true → chạy tự động, không hiện popup alert (dùng cho autoRun)
    function generateQR(silent) {
        const name = inputs.name.value.trim();
        const bank = inputs.bank.value.trim();
        const account = inputs.account.value.trim();
        const content = inputs.content.value.trim();
        const amount = inputs.amount.value.trim().replace(/[^\d]/g, ''); // Only digits
        let idbank = null;
        const bankLower = bank.toLowerCase();

        for (const [key, value] of Object.entries(bankMapping)) {
            if (bankLower.includes(key.toLowerCase())) {
                idbank = value;
                break;
            }
        }

        if (!idbank) {
            if (!silent) alert('⚠️ Không tìm thấy mã ngân hàng! Vui lòng kiểm tra tên ngân hàng.');
            return;
        }
        if (!name || !bank || !account || !amount) {
            if (!silent) alert('⚠️ Vui lòng điền đầy đủ: Tên, Ngân hàng, Số TK, Số tiền!');
            return;
        }

        // Generate VietQR URL
        // Format: https://img.vietqr.io/image/{BANK_ID}-{ACCOUNT_NO}-{TEMPLATE}.png?amount={AMOUNT}&addInfo={CONTENT}&accountName={NAME}
        const qrUrl = `https://api.vietqr.io/image/${idbank}-${encodeURIComponent(account)}-compact2.png?amount=${amount}&addInfo=${encodeURIComponent(content)}&accountName=${encodeURIComponent(name)}`;
        // Display QR code
        GM_xmlhttpRequest({
            method: 'GET',
            url: qrUrl,
            responseType: 'blob',
            onload: function(response) {
                const blobUrl = URL.createObjectURL(response.response);
                let qrImage;

                if (!document.getElementById('qrDisplay')) {
                    const qrContainer = document.createElement('div');
                    qrContainer.id = 'qrDisplay';
                    qrContainer.style.cssText = `
                        margin-top: 10px;
                        padding: 10px;
                        background-color: white;
                        border-radius: 5px;
                        text-align: center;
                    `;

                    qrImage = document.createElement('img');
                    qrImage.id = 'qrImage';
                    qrImage.style.cssText = 'max-width: 220px; width: 100%; border-radius: 5px;';
                    qrImage.src = blobUrl;

                    qrContainer.appendChild(qrImage);
                    container.appendChild(qrContainer);
                } else {
                    qrImage = document.getElementById('qrImage');
                    qrImage.src = blobUrl;
                }

                // QR tải xong → tự cuộn xuống để luôn nhìn thấy (panel nhỏ vẫn ổn)
                qrImage.onload = function() {
                    try { container.scrollTop = container.scrollHeight; } catch (e) {}
                };
            },
            onerror: function(error) {
                console.error('Error loading QR:', error);
                if (!silent) {
                    alert('❌ Không thể tải QR code. Thử mở link trong tab mới.');
                    window.open(qrUrl, '_blank');
                }
            }
        });
    }
    generateBtn.onclick = function() { generateQR(false); };
    buttonsContainer.appendChild(generateBtn);

    container.appendChild(buttonsContainer);

    // Add drag functionality
    let isDragging = false;
    let currentX;
    let currentY;
    let initialX;
    let initialY;

    title.style.cursor = 'move';
    title.onmousedown = function(e) {
        isDragging = true;
        initialX = e.clientX - container.offsetLeft;
        initialY = e.clientY - container.offsetTop;
    };

    document.onmousemove = function(e) {
        if (isDragging) {
            e.preventDefault();
            currentX = e.clientX - initialX;
            currentY = e.clientY - initialY;
            container.style.left = currentX + 'px';
            container.style.top = currentY + 'px';
            container.style.right = 'auto';
        }
    };

    document.onmouseup = function() {
        isDragging = false;
    };

    // Gắn GUI vào trang (script chạy ở document-start nên phải chờ body sẵn sàng)
    function mount() {
        if (!document.body) return;
        document.body.appendChild(container);
        guiReady = true;
        autoRun();   // nếu đã bắt được đơn trước khi GUI hiện ra → chạy luôn
    }
    if (document.body) {
        mount();
    } else {
        document.addEventListener('DOMContentLoaded', mount);
    }

})();
