Official Microsoft Solutions
1. Disable Shared Calendar Improvements (Primary Workaround)
Microsoft explicitly recommends this as the workaround for multiple calendar sharing issues :
In Outlook, select File → Account Settings → Account Settings
Select the Microsoft Exchange account and choose Change...
Choose More Settings, then the Advanced tab
Uncheck the box next to: "Turn on shared calendar improvements"
Select OK and restart Outlook when prompted
Close and reopen Outlook completely
Verification: After disabling, right-click the calendar → Properties → General tab. The Type should display "Folder containing Calendar items (MAPI)". If it shows "Folder containing Calendar items (REST)", the feature is still active and you must remove and re-add the calendar .
2. Clear Cached Data and Re-sync
Microsoft documentation recommends clearing offline items to force a re-sync with the server :
Open the Calendar pane in Outlook
Right-click the Calendar folder and select Properties
On the General tab, choose Clear Offline Items
Outlook will re-sync the calendar with server items
3. Remove and Re-add the Calendar
If the incorrect name persists after disabling Shared Calendar Improvements :
Remove the affected calendar(s) from Outlook Desktop
Ensure "Turn on shared calendar improvements" is disabled
Restart Outlook
Re-add the calendar(s) via Add Calendar → From Address Book
4. Address Book Synchronization
For the incorrect name display in the address book, Microsoft suggests :
Clear Auto-Complete Cache: Remove the incorrect name from the auto-complete dropdown when typing in the To field
Use Global Address List: Click To button and select the user directly from the Global Address List rather than using auto-complete
Download Latest Address Book: Go to Send/Receive → Send/Receive Groups → Download Address Book
