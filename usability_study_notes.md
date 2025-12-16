# AIS Feeder Initial Setup - Usability Study Notes

**Date:** 2025-12-08  
**Device URL:** http://5940da3a-porttracker-sdr.local  
**User Profile:** Non-technical user attempting first-time setup  
**Outcome:** Setup completed successfully

---

## Overview

The initial setup process involved three main phases:

1. Location Setup (entering station name, coordinates, altitude, and timezone)
2. SDR Setup (selecting the device and configuring it for AIS reception)
3. Waiting for configuration to be applied

The setup was completed successfully and the device is now configured to receive AIS messages.

---

## Observations and Improvement Suggestions

### 1. Initial Page - Location Setup

**What worked well:**

- The page clearly indicates this is the first step in setup
- The link to an external tool for finding coordinates/altitude is helpful
- Required field indicators are present

**Potential improvements:**

#### 1.1 "Station name" terminology

- **Issue:** The term "station name" might be unfamiliar to non-technical users. They might wonder if this refers to some pre-assigned identifier or if they should use a specific format.
- **Suggestion:** Consider adding placeholder text like "e.g., MyHomeReceiver" or a brief tooltip explaining they can choose any name.

#### 1.2 Altitude input format

- **Issue:** The label "Altitude above mean sea level" is technically accurate but could be confusing. Users might not know their altitude or understand the difference between various altitude references.
- **Suggestion:**
  - Simplify to "Altitude (meters)" with an explanatory note
  - Make it clearer that the external tool can provide this value
  - Consider auto-filling altitude when coordinates are entered (via API)

#### 1.3 "Fill in browser timezone" button feedback

- **Issue:** After clicking this button, there's no immediate visual feedback showing what value was selected. The user must look at the dropdown to verify it worked.
- **Suggestion:** Add a brief toast notification or visual highlight on the dropdown showing "Timezone set to [X]" to confirm the action.

#### 1.4 Coordinate format guidance

- **Issue:** No clear indication of the expected format for latitude and longitude (decimal degrees vs. degrees/minutes/seconds).
- **Suggestion:** Add placeholder text showing the expected format (e.g., "52.5200" for latitude).

---

### 2. Waiting/Progress Pages

**Major usability concern:**

#### 2.1 Overwhelming technical log output

- **Issue:** During configuration, the page displays raw log output showing Docker container operations, downloads, and extractions. This is extremely confusing and potentially alarming for non-technical users. They may:
  - Think something is broken
  - Not understand what's happening
  - Feel anxious about the technical-looking output
  - Not know if they should wait or take action
- **Suggestion:**
  - Replace the raw log output with a clean progress interface showing simple steps like:
    - "Step 1 of 3: Downloading software..."
    - "Step 2 of 3: Installing components..."
    - "Step 3 of 3: Configuring your device..."
  - Provide an optional "Show technical details" expandable section for advanced users
  - Display an estimated remaining time or progress percentage

#### 2.2 No progress indicator

- **Issue:** There's no visual indication of progress (spinner, progress bar, or percentage). Users don't know if the system is working or frozen.
- **Suggestion:** Add a clear animated spinner and/or progress bar with status text.

#### 2.3 Unclear wait time expectations

- **Issue:** Users have no idea how long the setup will take (it took approximately 1-2 minutes in this test).
- **Suggestion:** Add text like "This usually takes 1-3 minutes. Please don't close this page."

---

### 3. SDR Setup Page

**What worked well:**

- The SDR device was automatically detected
- AIS option was pre-selected and clearly visible
- "Apply settings" button is prominent

**Potential improvements:**

#### 3.1 Technical device name

- **Issue:** The device is displayed as "RTL2832U serial 00000001" which is meaningless to most users.
- **Suggestion:** Add a friendly description like "SDR Receiver (RTL2832U)" or "Your USB radio receiver" with the technical details available but de-emphasized.

#### 3.2 Checkbox vs. radio button confusion

- **Issue:** If AIS is the only option for this device type, it might be confusing to have it as a checkbox (implying multiple options exist).
- **Suggestion:** If only one option is valid, consider making it a pre-selected state with explanatory text rather than a checkbox.

#### 3.3 What happens next?

- **Issue:** No clear indication of what will happen when "Apply settings" is clicked.
- **Suggestion:** Add text like "Click Apply to start receiving AIS messages. The device will restart briefly."

---

### 4. Overview Page (Post-Setup)

**What worked well:**

- Clear status indication that the feeder is running
- Station name and configuration displayed prominently
- Message about "No positions received" is clear and not alarming

**Potential improvements:**

#### 4.1 First-time setup success message

- **Issue:** When setup completes, users land on the Overview page without any celebration or confirmation that setup was successful.
- **Suggestion:** Display a success message like "🎉 Setup Complete! Your AIS receiver is now running." This could be a dismissible banner at the top.

#### 4.2 Next steps guidance

- **Issue:** After setup, a new user might not know what to do next or what to expect.
- **Suggestion:** Add a "Getting Started" section or tips for first-time users, such as:
  - "Connect an antenna to start receiving AIS messages"
  - "It may take a few minutes for ships to be detected"
  - Links to help documentation or troubleshooting

---

### 5. Aggregators Page (Data Sharing)

**What worked well:**

- Clear categorization with tabs (AIS tab visible)
- Well-known aggregator services are listed (Porttracker, AIS-catcher, Aishub)
- Checkbox-based opt-in approach is intuitive

**Potential improvements:**

#### 5.1 Explanation of purpose

- **Issue:** Users may not understand what "aggregators" are or why they would want to share data with them.
- **Suggestion:** Add an introductory paragraph explaining what data sharing does and the benefits (e.g., "Share your AIS data with marine tracking services to help build a global vessel tracking network and contribute to maritime safety.")

#### 5.2 Missing from initial setup flow

- **Issue:** The Aggregators page is not part of the initial setup wizard flow. Users only discover it if they explore the navigation.
- **Suggestion:** Consider adding data sharing as an optional final step in the setup wizard, or display a prominent "Set up data sharing" call-to-action on the Overview page.

#### 5.3 What each aggregator is

- **Issue:** Users might not know what "Porttracker" or "AIS-catcher" are.
- **Suggestion:** Add brief descriptions or tooltips for each aggregator service explaining what they are and why a user might want to share data with them.

---

### 6. General/Navigation Improvements

#### 6.1 Setup wizard concept

- **Suggestion:** Consider implementing a traditional wizard-style setup with:
  - Step indicator (Step 1 of 3, Step 2 of 3, etc.)
  - Back button to modify previous steps
  - Clear "Next" and "Previous" navigation

#### 6.2 Help and documentation links

- **Issue:** There are no visible links to documentation or help throughout the interface.
- **Suggestion:** Add a help icon or "Need help?" link on each page pointing to relevant documentation.

#### 6.3 Mobile responsiveness

- **Note:** Did not test on mobile, but given the potential use case for headless device setup from a phone, this should be verified.

---

## Summary

The setup process was successful and relatively straightforward. The main areas for improvement center around:

1. **Reducing technical jargon** - Make language more accessible to non-technical users
2. **Better progress feedback** - Hide raw logs, show friendly progress indicators
3. **User guidance** - Add more context, explanations, and next-step suggestions
4. **Visual feedback** - Confirm actions and celebrate successful completion

The fundamentals are solid - the setup flow is logical and the automatic SDR detection is excellent. With some UX polish, this could be very accessible to non-technical users.
