import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import csv
import re
import pandas as pd

# --- CONFIGURATION ---
# Enter the exact search query you want to use
SEARCH_QUERY = 'label:clients-awr-4xx-alerts after:2026/02/01 before:2026/02/10'
CSV_FILENAME = 'gmail_scrape_report.csv'

def extract_data_from_body(subject, body_text, date_text):
    """
    Parses the raw text to find your specific values.
    """
    # 1. Regex for Trigger Value (handles newlines)
    trigger_match = re.search(r'above threshold[\s\S]*?value of\s*\*?(\d+)', body_text, re.IGNORECASE)
    trigger_val = trigger_match.group(1) if trigger_match else "-"
    
    # 2. Regex for Closing Value
    close_match = re.search(r'below threshold[\s\S]*?value of\s*\*?(\d+)', body_text, re.IGNORECASE)
    close_val = close_match.group(1) if close_match else "-"
    
    # 3. Regex for Metadata from Subject
    proj_match = re.search(r'project_id=([^,|}]+)', subject)
    proj_id = proj_match.group(1).strip() if proj_match else "-"
    
    url_match = re.search(r'url_map_name=([^,|}]+)', subject)
    url_map = url_match.group(1).strip() if url_match else "-"
    
    code_match = re.search(r'(\d{3}) Response Codes', subject)
    resp_code = code_match.group(1) if code_match else "4xx"

    # 4. Status Logic
    status = "Resolved" if (close_val != "-" or "recovered" in body_text.lower()) else "Unresolved"

    return [date_text, status, trigger_val, close_val, resp_code, proj_id, url_map, subject, body_text]

def main():
    print("🚀 Initializing Chrome...")
    options = uc.ChromeOptions()
    # options.add_argument('--headless') # Keep this commented out to see the browser!
    driver = uc.Chrome(options=options)

    try:
        # 1. LOGIN PHASE
        driver.get("https://mail.google.com/")
        print("\n" + "="*50)
        print("ACTION REQUIRED: Log in to Gmail in the browser window.")
        print("Handle your SAML/SSO/2FA manually.")
        input("👉 Press ENTER here in the terminal once your Inbox is fully loaded...")
        print("="*50 + "\n")

        # 2. SEARCH PHASE
        print(f"🔍 Searching for: {SEARCH_QUERY}")
        search_box = driver.find_element(By.NAME, "q")
        search_box.clear()
        search_box.send_keys(SEARCH_QUERY)
        search_box.send_keys(Keys.RETURN)
        
        time.sleep(5) # Wait for results to load

        # 3. OPEN FIRST EMAIL
        # We find the first email in the list and click it
        try:
            # Generic selector for email rows in result list
            first_email = driver.find_element(By.CSS_SELECTOR, 'div[role="main"] table tr')
            first_email.click()
            time.sleep(2)
        except:
            print("❌ Could not click the first email. Are there any results?")
            return

        # 4. EXTRACTION LOOP
        with open(CSV_FILENAME, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Date", "Status", "Trigger Value", "Closing Value", "Response Code", "Project ID", "URL Map", "Subject", "Full Body"])
            
            count = 0
            while True:
                try:
                    # -- A. SCRAPE CURRENT VIEW --
                    # Subject is usually in an h2 with class 'hP'
                    subject_elem = WebDriverWait(driver, 3).until(EC.presence_of_element_located((By.CSS_SELECTOR, "h2.hP")))
                    subject = subject_elem.text

                    # Date is usually in a span with class 'g3' or 'odt' - checking title attribute for full date
                    try:
                        date_elem = driver.find_element(By.CSS_SELECTOR, "span.g3")
                        date_text = date_elem.get_attribute("title") # Gets full timestamp
                    except:
                        date_text = "Unknown"

                    # Body text: The main email content div (class a3s is standard for gmail body)
                    body_elem = driver.find_element(By.CSS_SELECTOR, "div.a3s")
                    body_text = body_elem.text

                    # -- B. PARSE & SAVE --
                    row = extract_data_from_body(subject, body_text, date_text)
                    writer.writerow(row)
                    
                    count += 1
                    print(f"✅ Scraped email #{count}: {subject[:50]}...")

                    # -- C. GO TO NEXT EMAIL --
                    # We look for the "Older" button (Next Email) in the top toolbar
                    # The aria-label is usually "Older" or "Older conversation"
                    try:
                        # Try finding the "Older" button
                        next_button = driver.find_element(By.CSS_SELECTOR, "div[aria-label='Older'], div[aria-label='Older conversation']")
                        
                        # Check if it's disabled (end of list)
                        if "aria-disabled" in next_button.get_attribute("outerHTML") and "true" in next_button.get_attribute("aria-disabled"):
                            print("🎉 Reached the end of the list!")
                            break
                        
                        next_button.click()
                        time.sleep(1.5) # Small pause for load (adjust if connection is slow)
                        
                    except Exception as e:
                        print(f"⚠️ Could not find 'Next' button. Stopping. ({e})")
                        break

                except Exception as e:
                    print(f"❌ Error on email #{count + 1}: {e}")
                    break

    except Exception as e:
        print(f"CRITICAL ERROR: {e}")
    finally:
        print(f"\n📄 Data saved to {CSV_FILENAME}")
        print("Browser closing in 5 seconds...")
        time.sleep(5)
        driver.quit()

if __name__ == "__main__":
    main()
