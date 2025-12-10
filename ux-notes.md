Based on my exploration of the application and the code, here is a breakdown of UX improvements tailored for inexperienced users.

1. Network Setup (The biggest hurdle)
   WiFi Scanning: Currently, the user must type the SSID. This is error-prone (case sensitivity, typos).
   Recommendation: Implement a "Scan for Networks" feature that populates a dropdown list. Users are used to picking their WiFi from a list on their phone/laptop.
   Feedback Loop: The text warns that "it can take several minutes" and "a forced reboot may be required." This is scary for a beginner.
   Recommendation: If possible, provide a "Test Connection" button that tries to bring up the interface without committing it permanently, or a visual countdown/status indicator during the reconnection phase so they don't panic and pull the plug too early.
2. Location Setup
   Browser Geolocation: (I see we started looking at this). A "Use My Current Location" button is essential. Most users don't know their exact latitude/longitude.
   Altitude Units: The input asks for "m" or "ft" in the text string (e.g., 30m).
   Recommendation: Split this into two fields: a number input and a dropdown for Unit (Meters/Feet). This prevents parsing errors and confusion.
   Visual Confirmation: Users might mess up +/- signs for Lat/Lon.
   Recommendation: Embed a small, static map (like Leaflet.js or OpenStreetMap static image) that updates when they type. Seeing a pin in the ocean vs. their house is an instant validation.
3. SDR Setup
   Gain Control: The current input is a text field accepting numbers or "auto".
   Recommendation: Use a Slider for the gain value (0-50). Add a checkbox for "Automatic Gain". When "Automatic" is checked, the slider is disabled. This is much more intuitive than typing values.
   Jargon Translation: Terms like "Bias-T" are meaningless to a novice.
   Recommendation: Label it "Power Antenna (Bias-T)" or add a helper text: "Enable this if your antenna requires power from the receiver."
   Device Identification: The serial numbers and USB IDs are technical.
   Recommendation: If possible, assign friendly names (e.g., "Orange Stick", "Blue Stick") or allow the user to "Blink" the device (if hardware supports it) or just highlight the one currently receiving data.
4. General Workflow (The "Wizard" Approach)
   Linear Onboarding: The "Setup" dropdown requires the user to know what order to do things in.
   Recommendation: For a fresh install, present a "Setup Wizard" that guides them step-by-step:
   Welcome & Password (Secure the device)
   Network (Get online)
   Location (Where am I?)
   Radio (What am I hearing?)
   Done!
   "Apply" Anxiety: As you noted in

ux-notes.md
, users might forget to click Apply.
Recommendation: A "Save & Continue" button in the Wizard context works best. For individual pages, highlighting the "Apply" button (making it pulse or change color) when settings are changed but not saved is a common pattern. 5. Visual Polish
Status Indicators: The "Overview" page is good, but simple Red/Green dots for "Feeder Connected", "GPS Locked", "Internet Connected" at the top of every page helps users troubleshoot instantly without digging.
Would you like me to create a detailed implementation plan for any specific one of these areas (like the WiFi scanner or the Gain Slider)?
