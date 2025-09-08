#!/usr/bin/env python3
"""
Restore the complete CSS including both logo styling and reduced boldness
"""

import requests

AUTHENTIK_TOKEN = "tICEfnbnqwVI3K4KnWIytFUb7qfmIq1C9qeXYb1I4jJVMOVTJJApDfSmedPA"
AUTHENTIK_BASE_URL = "https://id.visiquate.com"

def authentik_request(method, endpoint, data=None):
    """Make authenticated request to Authentik API"""
    headers = {
        "Authorization": f"Bearer {AUTHENTIK_TOKEN}",
        "Content-Type": "application/json"
    }
    
    url = f"{AUTHENTIK_BASE_URL}{endpoint}"
    
    if method.upper() == 'PATCH':
        response = requests.patch(url, headers=headers, json=data, timeout=15)
    
    return response

def get_complete_css():
    """Get the complete CSS with both logo styling and reduced boldness"""
    
    original_logo_css = """/* === Authentik Brand — unified theme-aware logos ===
   Replace your entire Custom CSS with this block
*/

/* 0) Keep your existing footer-hide */
ak-brand-links { display: none !important; }

/* ---------------------------------------------------
   1) ADMIN PANEL (wrapper is <div class="logo"><img …>)
   --------------------------------------------------- */
div.logo {
  display: inline-block !important;
  width: 142px !important;   /* admin logo size */
  height: 36px !important;
  background-repeat: no-repeat !important;
  background-position: center !important;
  background-size: contain !important;
}
div.logo > img { display: none !important; }

@media (prefers-color-scheme: light) {
  div.logo {
    background-image: url("https://pub-a7c92cee044442f2a834bf15b1a4df63.r2.dev/logo-light.svg") !important;
  }
}
@media (prefers-color-scheme: dark) {
  div.logo {
    background-image: url("https://pub-a7c92cee044442f2a834bf15b1a4df63.r2.dev/logo-dark.svg") !important;
  }
}

/* ---------------------------------------------------
   2) USER PANEL (PatternFly header uses <img class="pf-c-brand">)
   — This does NOT target the login page (no pf-c-brand on the login <img>)
   --------------------------------------------------- */
@media (prefers-color-scheme: light) {
  img.pf-c-brand {
    content: url("https://pub-a7c92cee044442f2a834bf15b1a4df63.r2.dev/logo-light.svg") !important;
    width: 142px !important;
    height: 36px !important;
    display: inline-block !important;
  }
}
@media (prefers-color-scheme: dark) {
  img.pf-c-brand {
    content: url("https://pub-a7c92cee044442f2a834bf15b1a4df63.r2.dev/logo-dark.svg") !important;
    width: 142px !important;
    height: 36px !important;
    display: inline-block !important;
  }
}

/* If Safari ignores content:url on <img>, you can use this fallback instead:
.pf-c-masthead__brand img.pf-c-brand { display: none !important; }
.pf-c-masthead__brand {
  width: 142px !important;
  height: 36px !important;
  background-repeat: no-repeat !important;
  background-position: center !important;
  background-size: contain !important;
}
@media (prefers-color-scheme: light) {
  .pf-c-masthead__brand { background-image: url("https://pub-a7c92cee044442f2a834bf15b1a4df63.r2.dev/logo-light.svg") !important; }
}
@media (prefers-color-scheme: dark) {
  .pf-c-masthead__brand { background-image: url("https://pub-a7c92cee044442f2a834bf15b1a4df63.r2.dev/logo-dark.svg") !important; }
}
*/

/* ---------------------------------------------------
   3) LOGIN PAGE (PatternFly login)
   Wrapper is: <div class="pf-c-login__main-header pf-c-brand ak-brand"><img …>
   --------------------------------------------------- */
/* Hide only the login page's inline <img> */
.pf-c-login .pf-c-login__main-header.pf-c-brand.ak-brand > img[alt="authentik Logo"] {
  display: none !important;
}
/* Some builds also render a stray <img alt="authentik Logo"> — hide it on login only */
.pf-c-login img[alt="authentik Logo"] {
  display: none !important;
}
/* Paint the wrapper div as the logo (login uses larger art) */
.pf-c-login .pf-c-login__main-header.pf-c-brand.ak-brand {
  display: inline-block !important;
  width: 464px !important;   /* login logo size */
  height: 101px !important;
  background-repeat: no-repeat !important;
  background-position: center !important;
  background-size: contain !important;
}

@media (prefers-color-scheme: light) {
  .pf-c-login .pf-c-login__main-header.pf-c-brand.ak-brand {
    background-image: url("https://pub-a7c92cee044442f2a834bf15b1a4df63.r2.dev/logo-light.svg") !important;
  }
}
@media (prefers-color-scheme: dark) {
  .pf-c-login .pf-c-login__main-header.pf-c-brand.ak-brand {
    background-image: url("https://pub-a7c92cee044442f2a834bf15b1a4df63.r2.dev/logo-dark.svg") !important;
  }
}"""

    debold_css = """

/* ===== VisiQuate User Portal - Reduced Application Name Boldness ===== */

/* Reduce boldness of application names in the user portal library view */
.pf-c-card__title,
.pf-c-card__title a,
.pf-c-card__title-text {
    font-weight: 500 !important; /* Medium instead of bold */
}

/* Target the application tiles/cards in the user portal */
.ak-library-app .pf-c-card__title {
    font-weight: 500 !important;
}

/* Also target any app name links */
.ak-library-app a {
    font-weight: 500 !important;
}

/* Application list items */
.pf-c-data-list__item-main .pf-c-data-list__cell h3,
.pf-c-data-list__item-main .pf-c-data-list__cell a {
    font-weight: 500 !important;
}

/* Any bold application names in general */
.ak-application-name,
.application-name {
    font-weight: 500 !important;
}

/* Reduce PatternFly card title boldness globally for app tiles */
.pf-c-page__main .pf-c-card__title {
    font-weight: 500 !important;
}

/* Force light mode for better visibility */
:root {
    --pf-global--Color--light-100: #ffffff !important;
    --pf-global--BackgroundColor--light-100: #ffffff !important;
}
"""
    
    return original_logo_css + debold_css

def main():
    print("🔧 Restoring complete CSS with both logos and reduced boldness")
    
    complete_css = get_complete_css()
    
    update_data = {
        "attributes": {
            "custom_css": complete_css
        }
    }
    
    response = authentik_request('PATCH', '/api/v3/core/brands/ce9c6020-fb02-4028-9591-c90523a0feaf/', update_data)
    
    if response.status_code == 200:
        print("✅ Successfully restored complete CSS")
        print(f"   📋 Total CSS length: {len(complete_css)} characters")
        print("   🔗 Includes: Logo styling + Reduced app name boldness + Light mode")
    else:
        print(f"❌ Failed to update CSS: {response.status_code}")
        print(f"   Response: {response.text}")

if __name__ == "__main__":
    main()