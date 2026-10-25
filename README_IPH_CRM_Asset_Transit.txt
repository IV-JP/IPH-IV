IPH CRM — Asset Transit full code package

Files:
1. IPH_CRM_Center_Asset_Transit_Full_Code.gs — complete Apps Script backend file as retrieved from the latest available project artifact.
2. IPH_CRM_Center_Asset_Transit_Full_Frontend.html — complete HTML frontend as retrieved from the latest available project artifact.

Permissions intended:
- Center users can transfer only assets currently assigned to their own center to another destination center.
- Center users can confirm receipt only for transfers addressed to their center.
- Center users can cancel only transfers originated by their center.
- Admin/Super Admin can manage transfers globally.

Install:
1. Back up your current Apps Script Code.gs and HTML file.
2. Replace Code.gs with the supplied .gs file contents and replace the relevant CRM HTML with the supplied HTML file contents.
3. Save the project and deploy a new web app version.
4. Test a transfer from a center to a different center, then confirm receipt at the destination center.

Important:
These are the latest available artifacts from this conversation, not verified against your live Google Sheet or live deployment. Test with one non-critical asset first and verify Location, Transit Status, Transit Date, and Received Date in the sheet.
