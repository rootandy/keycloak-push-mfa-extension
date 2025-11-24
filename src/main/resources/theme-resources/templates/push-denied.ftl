<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=((messagesPerField?has_content)!false) || (messageSummary??); section>
    <#if section = "header">
        ${msg("push-mfa-title")}
    <#elseif section = "form">
        <style>
            .kc-push-card {
                background: var(--pf-v5-global--BackgroundColor--100, #fff);
                border: 1px solid var(--pf-v5-global--BorderColor--100, #d2d2d2);
                border-radius: 4px;
                box-shadow: var(--pf-global--BoxShadow--md, 0 1px 2px rgba(0, 0, 0, 0.1));
                padding: 1.5rem;
                margin-top: 1.5rem;
            }

            .kc-push-actions {
                display: flex;
                gap: 0.75rem;
                flex-wrap: wrap;
                margin-top: 1.5rem;
            }

            .kc-push-hint {
                margin-top: 0.75rem;
                color: var(--pf-v5-global--Color--200, #6a6e73);
                font-size: 0.95rem;
            }
        </style>

        <div class="${properties.kcContentWrapperClass!}">
            <div class="kc-push-card">
                <div class="alert alert-error">
                    ${msg("push-mfa-denied-message")!"The last push approval was denied."}
                </div>
                <p class="kc-push-hint">${msg("push-mfa-denied-hint")!"You can request a new push challenge to try again."}</p>
                <form action="${url.loginAction}" method="post" class="kc-push-actions">
                    <button class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!}"
                            type="submit">${msg("doTryAgain")}</button>
                </form>
            </div>
        </div>
    </#if>
</@layout.registrationLayout>
