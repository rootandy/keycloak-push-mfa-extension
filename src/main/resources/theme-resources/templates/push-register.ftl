<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=((messagesPerField?has_content)!false) || (messageSummary??); section>
    <#if section = "header">
        ${msg("push-mfa-register-title")}
    <#elseif section = "form">
        <style>
            .kc-push-register-grid {
                display: flex;
                flex-wrap: wrap;
                gap: 1.5rem;
                align-items: flex-start;
                margin-top: 1.5rem;
            }
            .kc-push-register-card {
                flex: 1 1 280px;
                background: var(--pf-global--BackgroundColor--100, #fff);
                border: 1px solid var(--pf-global--BorderColor--100, #d2d2d2);
                border-radius: 4px;
                padding: 1.25rem;
                box-shadow: var(--pf-global--BoxShadow--md, 0 1px 2px rgba(0, 0, 0, 0.1));
            }
            .kc-push-register-token-group {
                display: flex;
                flex-direction: column;
                gap: 0.75rem;
            }
            .kc-push-register-token {
                background: var(--pf-global--BackgroundColor--200, #f5f5f5);
                border: 1px solid var(--pf-global--BorderColor--200, #c7c7c7);
                border-radius: 4px;
                padding: 1rem;
                font-family: var(--pf-global--FontFamily--monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace);
                font-size: 0.9rem;
                max-height: 240px;
                overflow-y: auto;
                white-space: pre-wrap;
                word-break: break-word;
            }
            .kc-push-register-actions {
                display: flex;
                flex-wrap: wrap;
                gap: 0.75rem;
            }
            .kc-push-register__hint {
                margin-top: 0.5rem;
                color: var(--pf-global--Color--200, #6a6e73);
                font-size: 0.9rem;
            }
            .kc-push-register-qr {
                display: flex;
                align-items: center;
                justify-content: center;
                min-height: 240px;
                padding: 0.5rem;
                background: var(--pf-global--BackgroundColor--200, #f5f5f5);
                border: 1px dashed var(--pf-global--BorderColor--200, #c7c7c7);
                border-radius: 4px;
            }
            .kc-push-register-copy.copied {
                background: var(--pf-global--BackgroundColor--success, #3e8635);
                color: #fff;
            }
            @media (max-width: 680px) {
                .kc-push-register-card {
                    flex-basis: 100%;
                }
            }
        </style>

        <div class="${properties.kcContentWrapperClass!}">
            <div class="${properties.kcFormGroupClass!}">
                <p class="kc-push-register__hint">${msg("push-mfa-register-instructions", pushUsername!"")}</p>
                <p class="kc-push-register__hint">${msg("push-mfa-register-help")}</p>
            </div>

            <div class="kc-push-register-grid">
                <div class="kc-push-register-card">
                    <h3>${msg("push-mfa-register-qr-title")!"Scan to enroll"}</h3>
                    <div id="kc-push-qr" class="kc-push-register-qr" aria-live="polite"></div>
                    <p class="kc-push-register__hint">${msg("push-mfa-register-qr-hint")!"Scan with your companion app to autofill the enrollment token."}</p>
                </div>
                <div class="kc-push-register-card">
                    <h3>${msg("push-mfa-register-token-label")}</h3>
                    <div class="kc-push-register-token-group">
                        <pre id="kc-push-token" class="kc-push-register-token" tabindex="0">${enrollmentToken!''}</pre>
                        <div class="kc-push-register-actions">
                            <button id="kc-push-copy-token"
                                    type="button"
                                    class="${properties.kcButtonClass!} ${properties.kcButtonSecondaryClass!} kc-push-register-copy"
                                    data-default-label="${msg("push-mfa-register-copy-token")!"Copy token"}"
                                    data-success-label="${msg("push-mfa-register-copied")!"Copied"}">
                                ${msg("push-mfa-register-copy-token")!"Copy token"}
                            </button>
                        </div>
                        <p class="kc-push-register__hint">${msg("push-mfa-register-token-hint")}</p>
                    </div>
                </div>
            </div>

            <form id="kc-push-register-form" class="kc-push-register-actions" action="${url.loginAction}" method="post">
                <button class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!}" type="submit" name="confirm" value="true">
                    ${msg("push-mfa-register-confirm")!"I've enrolled"}
                </button>
                <button class="${properties.kcButtonClass!} ${properties.kcButtonSecondaryClass!}" type="submit" name="refresh" value="true">
                    ${msg("push-mfa-register-refresh")!"Generate new QR"}
                </button>
            </form>
            <form id="kc-push-register-poll" action="${url.loginAction}" method="post" style="display:none" aria-hidden="true">
                <input type="hidden" name="check" value="true"/>
            </form>
        </div>

        <script src="${url.resourcesPath}/js/qrcode.min.js"></script>
        <script>
            (function() {
                var copyButton = document.getElementById('kc-push-copy-token');
                var tokenElement = document.getElementById('kc-push-token');
                var qrContainer = document.getElementById('kc-push-qr');
                if (qrContainer && tokenElement && typeof QRCode !== 'undefined') {
                    var tokenValue = 'push-mfa-login-app://?token=' + tokenElement.textContent.trim();
                    if (tokenValue) {
                        qrContainer.innerHTML = "";
                        new QRCode(qrContainer, {
                            text: tokenValue,
                            width: 240,
                            height: 240,
                            correctLevel: QRCode.CorrectLevel.M
                        });
                    }
                }
                if (copyButton && tokenElement) {
                    var defaultLabel = copyButton.dataset.defaultLabel || copyButton.textContent;
                    var successLabel = copyButton.dataset.successLabel || 'Copied';
                    copyButton.addEventListener('click', function () {
                        var button = copyButton;
                        if (!button) {
                            return;
                        }
                        var textToCopy = tokenElement.textContent.trim();
                        var secureCopy = function () {
                            return (navigator.clipboard && window.isSecureContext)
                                ? navigator.clipboard.writeText(textToCopy)
                                : Promise.reject(new Error('Clipboard API unavailable'));
                        };
                        var fallbackCopy = function () {
                            return new Promise(function (resolve, reject) {
                                try {
                                    var temp = document.createElement('textarea');
                                    temp.value = textToCopy;
                                    temp.style.position = 'fixed';
                                    temp.style.opacity = '0';
                                    document.body.appendChild(temp);
                                    temp.focus();
                                    temp.select();
                                    var ok = document.execCommand && document.execCommand('copy');
                                    document.body.removeChild(temp);
                                    if (!ok) {
                                        throw new Error('execCommand failed');
                                    }
                                    resolve();
                                } catch (err) {
                                    reject(err);
                                }
                            });
                        };

                        secureCopy().catch(fallbackCopy).then(function () {
                            button.classList.add('copied');
                            button.textContent = successLabel;
                            setTimeout(function () {
                                button.classList.remove('copied');
                                button.textContent = defaultLabel;
                            }, 2000);
                        }).catch(function (error) {
                            console.error('Failed to copy token', error);
                            button.classList.remove('copied');
                            button.textContent = defaultLabel;
                        });
                    });
                }
            })();
            (function() {
                var pollForm = document.getElementById('kc-push-register-poll');
                var eventsUrl = '${(enrollEventsUrl!"")?js_string}';

                function submitPoll() {
                    if (!pollForm) {
                        return;
                    }
                    (pollForm.requestSubmit ? pollForm.requestSubmit() : pollForm.submit());
                }

                if (!eventsUrl) {
                    console.warn('push-mfa enrollment SSE unavailable: missing eventsUrl');
                    return;
                }
                if (typeof EventSource === 'undefined') {
                    console.warn('push-mfa enrollment SSE unavailable: EventSource unsupported in this browser');
                    return;
                }

                var source = new EventSource(eventsUrl);

                source.addEventListener('status', function (event) {
                    try {
                        var data = event && event.data ? JSON.parse(event.data) : null;
                        if (data && data.status && data.status !== 'PENDING') {
                            source.close();
                            submitPoll();
                        }
                    } catch (err) {
                        console.warn('push-mfa enrollment SSE parse error', err);
                    }
                });

                source.addEventListener('error', function (event) {
                    // Let EventSource handle reconnect; we only log for visibility.
                    console.warn('push-mfa enrollment SSE error (auto-retry handled by browser)', event);
                });
            })();
        </script>
    </#if>
</@layout.registrationLayout>
