#!/data/data/com.termux/files/usr/bin/bash

# ============================================
# CRITICAL BUG HUNTER - ULTIMATE EDITION
# ============================================
# Complete penetration testing suite for Termux
# ============================================

# [KONFIGURASI DAN FUNGSI UTAMA SAMA DENGAN SEBELUMNYA]

# ============================================
# ENHANCED SCANNING MODULES
# ============================================

run_complete_scan() {
    local target=$1
    echo -e "${PURPLE}[*] STARTING COMPLETE PENETRATION TEST${NC}"
    
    # Phase 1: Reconnaissance
    advanced_recon "$target"
    detect_technologies "$target"
    
    # Phase 2: Port & Service Scanning
    run_nmap_scans "$target"
    scan_with_nikto "$target"
    
    # Phase 3: Vulnerability Scanning
    ai_scan_rce "$target"
    ai_scan_sqli "$target"
    ai_scan_xxe "$target"
    ai_scan_ssrf "$target"
    ai_scan_idor "$target"
    
    # Phase 4: Web Application Testing
    scan_with_nuclei "$target"
    scan_with_dalfox "$target"
    automated_browser_testing "$target"
    
    # Phase 5: Authentication Testing
    hydra_bruteforce "$target"
    
    # Phase 6: Advanced Testing
    scan_for_secrets "$target"
    test_api_security "$target"
    
    # Phase 7: Generate Report
    generate_comprehensive_report "$target"
}

# ============================================
# NMAP COMPREHENSIVE SCANNING
# ============================================

run_nmap_scans() {
    local target=$1
    echo -e "${CYAN}[*] Running comprehensive Nmap scans${NC}"
    
    mkdir -p $OUTPUT_DIR/nmap
    
    # 1. Quick Scan (Common ports)
    echo -e "${BLUE}[+] Quick scan (top 1000 ports)${NC}"
    nmap -T4 -F "$target" -oN $OUTPUT_DIR/nmap/quick_scan.txt
    
    # 2. Full Port Scan
    echo -e "${BLUE}[+] Full port scan${NC}"
    nmap -T4 -p- "$target" -oN $OUTPUT_DIR/nmap/full_ports.txt
    
    # 3. Service Detection
    echo -e "${BLUE}[+] Service version detection${NC}"
    nmap -T4 -sV "$target" -oN $OUTPUT_DIR/nmap/service_versions.txt
    
    # 4. Vulnerability Scan
    echo -e "${BLUE}[+] Vulnerability scan${NC}"
    nmap -T4 --script vuln "$target" -oN $OUTPUT_DIR/nmap/vulnerabilities.txt
    
    # 5. NSE Scripts Categories
    scripts_categories=("exploit" "malware" "intrusive" "discovery" "auth" "broadcast")
    
    for category in "${scripts_categories[@]}"; do
        echo -e "${YELLOW}[+] Running $category scripts${NC}"
        nmap -T4 --script "$category" "$target" -oN $OUTPUT_DIR/nmap/${category}_scripts.txt 2>/dev/null &
    done
    
    wait
    
    # 6. OS Detection
    echo -e "${BLUE}[+] OS detection${NC}"
    nmap -T4 -O "$target" -oN $OUTPUT_DIR/nmap/os_detection.txt
    
    # 7. Firewall/IDS Evasion
    echo -e "${BLUE}[+] Firewall/IDS evasion tests${NC}"
    nmap -T4 -f --mtu 16 -D RND:10 "$target" -oN $OUTPUT_DIR/nmap/firewall_evasion.txt &
    nmap -T4 --source-port 53 "$target" -oN $OUTPUT_DIR/nmap/source_port_53.txt &
    
    wait
    
    echo -e "${GREEN}[√] Nmap scans completed${NC}"
}

# ============================================
# NIKTO SERVER SCANNING
# ============================================

scan_with_nikto() {
    local target=$1
    echo -e "${CYAN}[*] Running Nikto web server scanner${NC}"
    
    mkdir -p $OUTPUT_DIR/nikto
    
    # Remove protocol for Nikto
    local clean_target=$(echo "$target" | sed 's|https\?://||')
    
    # Basic Nikto scan
    nikto -h "$clean_target" -Format txt -output $OUTPUT_DIR/nikto/basic_scan.txt \
        -Tuning 123bde -timeout 30
    
    # Advanced scan with all tests
    nikto -h "$clean_target" -Format csv -output $OUTPUT_DIR/nikto/full_scan.csv \
        -Tuning 1234567890abc -timeout 60 -evasion 1 &
    
    # SSL/TLS specific scan if HTTPS
    if [[ "$target" == https* ]]; then
        nikto -h "$clean_target" -ssl -Format xml -output $OUTPUT_DIR/nikto/ssl_scan.xml \
            -Tuning a -timeout 30 &
    fi
    
    wait
    
    # Parse results
    echo -e "${BLUE}[+] Parsing Nikto results...${NC}"
    
    if [ -f "$OUTPUT_DIR/nikto/basic_scan.txt" ]; then
        # Extract critical findings
        grep -i "vulnerability\|danger\|warning\|critical" $OUTPUT_DIR/nikto/basic_scan.txt | \
            head -50 > $OUTPUT_DIR/nikto/critical_findings.txt
        
        # Count findings
        local vuln_count=$(grep -c "OSVDB-" $OUTPUT_DIR/nikto/basic_scan.txt)
        echo -e "${YELLOW}[!] Nikto found $vuln_count potential issues${NC}"
    fi
    
    echo -e "${GREEN}[√] Nikto scan completed${NC}"
}

# ============================================
# WAPPALYZER TECHNOLOGY DETECTION
# ============================================

detect_technologies() {
    local target=$1
    echo -e "${CYAN}[*] Detecting technologies with multiple tools${NC}"
    
    mkdir -p $OUTPUT_DIR/technology
    
    # Method 1: WhatWeb (fast and comprehensive)
    echo -e "${BLUE}[+] Running WhatWeb...${NC}"
    whatweb -a 3 "$target" --log-verbose=$OUTPUT_DIR/technology/whatweb.txt 2>/dev/null
    
    # Method 2: Builtin detection with curl
    echo -e "${BLUE}[+] Analyzing HTTP headers...${NC}"
    curl -s -I "$target" > $OUTPUT_DIR/technology/headers.txt
    curl -s "$target" | grep -i "powered-by\|framework\|version\|jquery\|react\|angular" | \
        head -20 > $OUTPUT_DIR/technology/indicators.txt
    
    # Method 3: Wappalyzer via Python
    echo -e "${BLUE}[+] Running technology detection...${NC}"
    python3 << EOF
import requests
import json
from bs4 import BeautifulSoup

try:
    response = requests.get('$target', timeout=10, verify=False)
    headers = dict(response.headers)
    html = response.text
    
    technologies = {}
    
    # Detect by headers
    if 'server' in headers:
        technologies['server'] = headers['server']
    if 'x-powered-by' in headers:
        technologies['powered_by'] = headers['x-powered-by']
    if 'x-aspnet-version' in headers:
        technologies['asp_net'] = headers['x-aspnet-version']
    
    # Detect by HTML patterns
    soup = BeautifulSoup(html, 'html.parser')
    
    # Meta tags
    for meta in soup.find_all('meta'):
        if 'generator' in meta.get('name', '').lower():
            technologies['generator'] = meta.get('content', '')
    
    # Script tags
    for script in soup.find_all('script'):
        src = script.get('src', '')
        if 'jquery' in src.lower():
            technologies['jquery'] = True
        if 'react' in src.lower():
            technologies['react'] = True
        if 'angular' in src.lower():
            technologies['angular'] = True
    
    # Write results
    with open('$OUTPUT_DIR/technology/detected.json', 'w') as f:
        json.dump(technologies, f, indent=2)
    
    print("Detected technologies:", json.dumps(technologies, indent=2))
    
except Exception as e:
    print(f"Error: {e}")
EOF
    
    # Method 4: BuiltWith-like detection
    echo -e "${BLUE}[+] Checking common frameworks...${NC}"
    
    # Check for common CMS
    cms_patterns=(
        "wp-content|wp-includes|wordpress"
        "joomla|administrator/components"
        "drupal|sites/all"
        "magento|skin/frontend"
        "laravel|storage/framework"
    )
    
    for pattern in "${cms_patterns[@]}"; do
        if curl -s "$target" | grep -qi "$pattern"; then
            cms=$(echo "$pattern" | cut -d'|' -f1)
            echo "[INFO] Possible $cms detected" >> $OUTPUT_DIR/technology/cms.txt
        fi
    done
    
    echo -e "${GREEN}[√] Technology detection completed${NC}"
}

# ============================================
# HYDRA BRUTE FORCE ATTACKS
# ============================================

hydra_bruteforce() {
    local target=$1
    echo -e "${RED}[*] Starting controlled brute-force attacks${NC}"
    
    read -p "Do you have permission for brute-force attacks? (yes/no): " permission
    if [ "$permission" != "yes" ]; then
        echo -e "${YELLOW}[!] Skipping brute-force attacks${NC}"
        return
    fi
    
    mkdir -p $OUTPUT_DIR/hydra
    
    local clean_target=$(echo "$target" | sed 's|https\?://||')
    local ip=$(dig +short "$clean_target" | head -1)
    
    if [ -z "$ip" ]; then
        ip="$clean_target"
    fi
    
    # Common service tests
    declare -A services=(
        ["ssh"]="22"
        ["ftp"]="21"
        ["telnet"]="23"
        ["mysql"]="3306"
        ["postgresql"]="5432"
        ["rdp"]="3389"
        ["smb"]="445"
    )
    
    for service in "${!services[@]}"; do
        port="${services[$service]}"
        
        echo -e "${YELLOW}[+] Testing $service on port $port...${NC}"
        
        # Check if port is open first
        if timeout 2 nc -z "$ip" "$port" 2>/dev/null; then
            echo -e "${GREEN}[√] Port $port ($service) is open${NC}"
            
            case $service in
                "ssh")
                    hydra -L $WORDLISTS_DIR/SecLists/Usernames/top-usernames-shortlist.txt \
                          -P $WORDLISTS_DIR/SecLists/Passwords/2020-200_most_used_passwords.txt \
                          ssh://$ip -t 4 -o $OUTPUT_DIR/hydra/${service}_results.txt 2>/dev/null &
                    ;;
                "ftp")
                    hydra -L $WORDLISTS_DIR/SecLists/Usernames/top-usernames-shortlist.txt \
                          -P $WORDLISTS_DIR/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt \
                          ftp://$ip -o $OUTPUT_DIR/hydra/${service}_results.txt 2>/dev/null &
                    ;;
                "mysql")
                    hydra -L $WORDLISTS_DIR/SecLists/Usernames/top-usernames-shortlist.txt \
                          -P $WORDLISTS_DIR/SecLists/Passwords/Common-Credentials/10k-most-common.txt \
                          mysql://$ip -o $OUTPUT_DIR/hydra/${service}_results.txt 2>/dev/null &
                    ;;
            esac
            
            sleep 1
        else
            echo -e "${BLUE}[!] Port $port ($service) is closed${NC}"
        fi
    done
    
    # Web form brute-force
    echo -e "${YELLOW}[+] Testing web login forms...${NC}"
    
    # Find login pages
    login_pages=(
        "/login"
        "/admin"
        "/administrator"
        "/wp-login.php"
        "/user/login"
        "/signin"
        "/auth"
    )
    
    for page in "${login_pages[@]}"; do
        if curl -s "$target$page" | grep -qi "login\|password\|username"; then
            echo -e "${GREEN}[√] Found login page: $page${NC}"
            
            # Test with common credentials
            hydra -L $WORDLISTS_DIR/SecLists/Usernames/top-usernames-shortlist.txt \
                  -P $WORDLISTS_DIR/SecLists/Passwords/2020-200_most_used_passwords.txt \
                  $target http-post-form "$page:username=^USER^&password=^PASS^:F=incorrect" \
                  -o $OUTPUT_DIR/hydra/web_${page//\//_}_results.txt 2>/dev/null &
        fi
    done
    
    wait
    
    # Check for successful compromises
    success_count=$(grep -r "login:" $OUTPUT_DIR/hydra/ 2>/dev/null | wc -l)
    if [ $success_count -gt 0 ]; then
        echo -e "${RED}[!] $success_count successful logins found!${NC}"
        grep -r "login:" $OUTPUT_DIR/hydra/ 2>/dev/null > $OUTPUT_DIR/hydra/successful_logins.txt
    else
        echo -e "${GREEN}[√] No successful logins found${NC}"
    fi
    
    echo -e "${GREEN}[√] Brute-force attacks completed${NC}"
}

# ============================================
# SELENIUM/PUPPETEER AUTOMATION
# ============================================

automated_browser_testing() {
    local target=$1
    echo -e "${CYAN}[*] Starting automated browser testing${NC}"
    
    mkdir -p $OUTPUT_DIR/browser
    
    # Create Python automation script
    python3 << EOF
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
import time
import os

# Setup Firefox options
options = webdriver.FirefoxOptions()
options.add_argument('--headless')
options.add_argument('--no-sandbox')
options.add_argument('--disable-dev-shm-usage')

# Create output directory
output_dir = "$OUTPUT_DIR/browser"
os.makedirs(output_dir, exist_ok=True)

driver = None
try:
    print("[*] Launching Firefox...")
    driver = webdriver.Firefox(options=options)
    driver.set_page_load_timeout(30)
    
    print(f"[*] Navigating to {target}...")
    driver.get('$target')
    
    # Wait for page load
    time.sleep(3)
    
    # 1. Take screenshot
    print("[*] Taking screenshot...")
    driver.save_screenshot(f'{output_dir}/screenshot.png')
    
    # 2. Save page source
    print("[*] Saving page source...")
    with open(f'{output_dir}/page_source.html', 'w', encoding='utf-8') as f:
        f.write(driver.page_source)
    
    # 3. Extract all links
    print("[*] Extracting links...")
    links = driver.find_elements(By.TAG_NAME, 'a')
    with open(f'{output_dir}/links.txt', 'w') as f:
        for link in links:
            href = link.get_attribute('href')
            if href:
                f.write(f'{href}\\n')
    
    print(f"[*] Found {len(links)} links")
    
    # 4. Find and analyze forms
    print("[*] Analyzing forms...")
    forms = driver.find_elements(By.TAG_NAME, 'form')
    
    with open(f'{output_dir}/forms_analysis.txt', 'w') as f:
        f.write(f"Total forms: {len(forms)}\\n\\n")
        
        for i, form in enumerate(forms):
            f.write(f"\\n=== Form {i+1} ===\\n")
            
            # Get form attributes
            form_id = form.get_attribute('id') or 'No ID'
            form_action = form.get_attribute('action') or 'No action'
            form_method = form.get_attribute('method') or 'GET'
            
            f.write(f"ID: {form_id}\\n")
            f.write(f"Action: {form_action}\\n")
            f.write(f"Method: {form_method}\\n")
            
            # Find all inputs
            inputs = form.find_elements(By.TAG_NAME, 'input')
            f.write(f"Inputs: {len(inputs)}\\n")
            
            for input_elem in inputs:
                input_type = input_elem.get_attribute('type') or 'text'
                input_name = input_elem.get_attribute('name') or 'No name'
                f.write(f"  - {input_name} ({input_type})\\n")
    
    # 5. Test for XSS vulnerable forms
    print("[*] Testing forms for XSS vulnerability...")
    xss_payloads = ['<script>alert(1)</script>', '\"onmouseover=\"alert(1)']
    
    for i, form in enumerate(forms[:3]):  # Test first 3 forms
        try:
            inputs = form.find_elements(By.TAG_NAME, 'input')
            for input_elem in inputs:
                if input_elem.get_attribute('type') in ['text', 'search', 'email']:
                    input_elem.clear()
                    input_elem.send_keys(xss_payloads[0])
            
            # Try to submit
            submit_buttons = form.find_elements(By.XPATH, './/input[@type=\"submit\"]')
            if submit_buttons:
                submit_buttons[0].click()
                time.sleep(2)
                
                # Check if alert appears
                try:
                    alert = driver.switch_to.alert
                    alert_text = alert.text
                    alert.accept()
                    print(f"[!] XSS alert triggered in form {i+1}: {alert_text}")
                    
                    with open(f'{output_dir}/xss_vulnerable.txt', 'a') as f:
                        f.write(f"Form {i+1}: XSS vulnerability confirmed\\n")
                except:
                    pass
                    
        except Exception as e:
            print(f"[!] Error testing form {i+1}: {e}")
    
    # 6. Check for sensitive data in JavaScript
    print("[*] Checking for sensitive data...")
    scripts = driver.find_elements(By.TAG_NAME, 'script')
    
    sensitive_patterns = ['api_key', 'apikey', 'secret', 'password', 'token', 'auth']
    found_secrets = []
    
    for script in scripts:
        js_code = script.get_attribute('innerHTML')
        if js_code:
            for pattern in sensitive_patterns:
                if pattern.lower() in js_code.lower():
                    found_secrets.append(f"Found '{pattern}' in script")
    
    if found_secrets:
        with open(f'{output_dir}/sensitive_data.txt', 'w') as f:
            f.write('\\n'.join(found_secrets))
        print(f"[!] Found {len(found_secrets)} potential secrets")
    
    # 7. Test for clickjacking vulnerability
    print("[*] Testing for clickjacking...")
    if 'X-Frame-Options' not in driver.execute_script("return JSON.stringify(arguments[0].headers)", driver.execute_script("return performance.getEntries()[0]")):
        with open(f'{output_dir}/clickjacking.txt', 'w') as f:
            f.write("VULNERABLE: Missing X-Frame-Options header\\n")
        print("[!] Clickjacking vulnerability detected")
    
    print("[√] Browser automation completed")
    
except Exception as e:
    print(f"[!] Error during browser automation: {e}")
    
finally:
    if driver:
        driver.quit()
EOF

    # Run Puppeteer for additional testing
    echo -e "${BLUE}[+] Running Puppeteer tests...${NC}"
    
    node << EOF
const puppeteer = require('puppeteer');
const fs = require('fs');

(async () => {
    const outputDir = "$OUTPUT_DIR/browser";
    
    const browser = await puppeteer.launch({
        headless: 'new',
        args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    
    const page = await browser.newPage();
    
    // Set viewport
    await page.setViewport({ width: 1366, height: 768 });
    
    // Capture console logs
    page.on('console', msg => {
        const text = msg.text();
        if (text.includes('Error') || text.includes('Warning')) {
            fs.appendFileSync(\`\${outputDir}/console_errors.txt\`, \`\${msg.type()}: \${text}\\n\`);
        }
    });
    
    // Capture errors
    page.on('pageerror', error => {
        fs.appendFileSync(\`\${outputDir}/page_errors.txt\`, \`\${error.message}\\n\`);
    });
    
    // Capture requests
    const requests = [];
    page.on('request', req => {
        requests.push(req.url());
    });
    
    try {
        // Navigate to target
        await page.goto('$target', { waitUntil: 'networkidle2', timeout: 30000 });
        
        // Take screenshot
        await page.screenshot({ path: \`\${outputDir}/puppeteer_screenshot.png\`, fullPage: true });
        
        // Save requests
        fs.writeFileSync(\`\${outputDir}/requests.txt\`, requests.join('\\n'));
        
        // Extract cookies
        const cookies = await page.cookies();
        fs.writeFileSync(\`\${outputDir}/cookies.json\`, JSON.stringify(cookies, null, 2));
        
        // Test for localStorage/sessionStorage
        const localStorageData = await page.evaluate(() => {
            return JSON.stringify(localStorage);
        });
        
        if (localStorageData && localStorageData !== '{}') {
            fs.writeFileSync(\`\${outputDir}/local_storage.json\`, localStorageData);
        }
        
        // Check for common vulnerabilities
        const securityHeaders = await page.evaluate(() => {
            return {
                hasCSP: document.querySelector('meta[http-equiv="Content-Security-Policy"]') !== null,
                hasHSTS: performance.getEntries()[0].nextHopProtocol === 'h2'
            };
        });
        
        fs.writeFileSync(\`\${outputDir}/security_headers.txt\`, 
            \`CSP: \${securityHeaders.hasCSP}\\nHSTS: \${securityHeaders.hasHSTS}\\n\`);
        
        console.log('[√] Puppeteer tests completed');
        
    } catch (error) {
        console.error('[!] Puppeteer error:', error);
    } finally {
        await browser.close();
    }
})();
EOF

    echo -e "${GREEN}[√] Automated browser testing completed${NC}"
}

# ============================================
# MAIN EXECUTION
# ============================================

# ... [rest of the script remains the same]

# Update main menu to include all modules
main_pro_menu() {
    while true; do
        show_pro_banner
        
        echo -e "${WHITE}Select an option:${NC}"
        echo -e "${GREEN}1. 🛠️  Install All Tools${NC}"
        echo -e "${GREEN}2. 🔍 Complete Penetration Test${NC}"
        echo -e "${CYAN}3. 🎯 SQL Injection (SQLMap)${NC}"
        echo -e "${CYAN}4. 🌐 Server Config (Nikto)${NC}"
        echo -e "${CYAN}5. 🔓 Port Scanning (Nmap)${NC}"
        echo -e "${CYAN}6. 🔧 Technology Detection (Wappalyzer)${NC}"
        echo -e "${CYAN}7. 🔐 Brute Force (Hydra)${NC}"
        echo -e "${CYAN}8. 🤖 Browser Automation${NC}"
        echo -e "${BLUE}9. 📊 Generate Report${NC}"
        echo -e "${RED}0. 🚪 Exit${NC}"
        echo ""
        
        read -p "Choice [0-9]: " choice
        
        case $choice in
            1) install_pro_tools ;;
            2) run_complete_scan "$TARGET" ;;
            3) ai_scan_sqli "$TARGET" ;;
            4) scan_with_nikto "$TARGET" ;;
            5) run_nmap_scans "$TARGET" ;;
            6) detect_technologies "$TARGET" ;;
            7) hydra_bruteforce "$TARGET" ;;
            8) automated_browser_testing "$TARGET" ;;
            9) generate_comprehensive_report "$TARGET" ;;
            0) exit 0 ;;
            *) echo -e "${RED}[!] Invalid choice${NC}" ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..."
    done
}
