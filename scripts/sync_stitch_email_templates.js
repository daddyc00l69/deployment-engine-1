const fs = require('fs');
const path = require('path');

function exists(p) {
    try { fs.accessSync(p); return true; } catch { return false; }
}

function safeWriteFile(outPath, content) {
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, content, 'utf8');
}

function transformTemplate(name, html) {
    let out = html;

    // 1) Email verification: button -> anchor with {{verify_link}}, and inject {{otp}}
    if (name === 'vpsphere_email_verification_email') {
        // Replace CTA button with a real link
        out = out.replace(
            /<button([^>]*)>\s*<span>\s*Verify Email\s*<\/span>[\s\S]*?<\/button>/i,
            `<a href="{{verify_link}}" style="text-decoration:none;"$1><span>Verify Email</span><span class="material-symbols-outlined text-lg">arrow_forward</span></a>`
        );

        // Replace any hardcoded example link with {{verify_link}}
        out = out.replace(/https?:\/\/[^\s<"]+/g, (m) => {
            if (m.includes('verify') || m.includes('auth/verify')) return '{{verify_link}}';
            return m;
        });

        // Ensure OTP placeholder is present somewhere visible
        if (!out.includes('{{otp}}')) {
            out = out.replace(
                /(<div class="mt-8[\s\S]*?<\/div>)/i,
                `$1\n<p style="margin-top:16px; font-size:14px;">Your verification code is: <strong style="font-size:18px; letter-spacing:0.12em;">{{otp}}</strong></p>`
            );
        }
    }

    // 2) Password reset request: button -> anchor with {{reset_link}}, remove stray admin profile block.
    if (name === 'vpsphere_password_reset_email') {
        out = out.replace(
            /<button([^>]*)>\s*Reset Password\s*<\/button>/i,
            `<a href="{{reset_link}}" style="text-decoration:none;"$1>Reset Password</a>`
        );
        if (!out.includes('{{reset_link}}')) {
            // If the template didn't have any reset link text, inject it near the CTA.
            out = out.replace(
                /(<a href="\{\{reset_link\}\}"[\s\S]*?<\/a>)/i,
                `$1\n<p class="text-xs" style="word-break:break-all; margin-top:12px;">{{reset_link}}</p>`
            );
        }

        // Remove known non-email artifact block if present
        out = out.replace(/<!-- External Profile Context[\s\S]*?<\/div>\s*<\/div>\s*<\/body>/i, '</div>\n</body>');
    }

    return out;
}

function main() {
    const sourceRoot = path.resolve(__dirname, '../../email template');
    const destRoot = path.resolve(__dirname, '../email/templates');

    if (!exists(sourceRoot)) {
        console.error(`Missing source templates folder: ${sourceRoot}`);
        process.exit(1);
    }

    const mappings = {
        // map Stitch folder names -> runtime template filenames used by mailers
        vpsphere_password_reset_request_email: 'vpsphere_password_reset_email',
    };

    const entries = fs.readdirSync(sourceRoot, { withFileTypes: true })
        .filter((d) => d.isDirectory())
        .map((d) => d.name);

    let written = 0;
    for (const dir of entries) {
        const codePath = path.join(sourceRoot, dir, 'code.html');
        if (!exists(codePath)) continue;

        const destName = mappings[dir] || dir;
        const raw = fs.readFileSync(codePath, 'utf8');
        const transformed = transformTemplate(destName, raw);
        const outPath = path.join(destRoot, `${destName}.html`);
        safeWriteFile(outPath, transformed);
        written += 1;
    }

    console.log(`Synced ${written} templates into ${destRoot}`);
}

if (require.main === module) main();

