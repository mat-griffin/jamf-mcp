# Jamf Pro MCP Server
⚠️ **EXPERIMENTAL - READ before use**

## Summary
The MCP server provides integration to Jamf Pro. It has only been tested in Cursor AI.
It allows for querying computer information by serial number, ID, user name from Cursor AI.
The AI will summarise and then ask you what else you might want to know.

## Security Warning
- Use a dedicated read-only Jamf test account.
- Delete the Jamf account credentials after use experimenting.

## Issues:
This is **EXPERIMENTAL**.
Therefore be prepared to delete or change the Jamf account & password after use.

## Prerequisites
- Cursor AI
- Homebrew
- Node.js
- Jamf Pro URL (format: https://myserver.jamfcloud.com/api)
- Jamf Pro read-only account

If Homebrew is not installed got to https://brew.sh and install.
Once brew is installed install node, the command below fails quit Terminal and then try again.

    brew install node

You will need your Jamf Pro URL plus `/api` at the end e.g. `https://myserver.jamfcloud.com/api`
A Jamf Pro readonly test account.


# Installation
These instructions have been written for Mac user.
Clone the project from Github or create a folder called `jamf_mcp` in your home directory and copy the following files into the folder:

`mcp_jamf_server.js`
`package-lock.json`
`package.json`

Open and edit `mcp_jamf_server.js`
Add your Jamf URL *(around line 18)* 
Add your Jamf username *(around line 22)* 
Add your Jamf and password *(around line 23)* 
Again I advise the Jamf account is read-only and is a throwaway account.

Open Terminal CD into the `jamf_mcp` folder.
**Enter:** `npm install`

Terminal will output similar to this:

    added 111 packages, and audited 112 packages in 991ms
    
    33 packages are looking for funding
      run `npm fund` for details
    
    found 0 vulnerabilities

**Enter:** `npm start`
The terminal should show similar to this:

    > jamf_mcp_test@1.0.0 start
    > node mcp_jamf_server.js
    
    Jamf MCP server running on stdio

The Jamf MCP server is now running 


## Using the MCP Server with Cursor AI
Launch Cursor.
Click *Open project* and select the `jamf_mcp` folder you cloned or created earlier.

In Cursor go to *Settings > MCP*

Click **Add new global MCP Server**.
Enter the mcp json connection details ensuring the path where you placed or cloned the files to is correct. 
In this example its `~/jamf_mcp/mcp_jamf_server.js` 

Or you can use a full path for example:  `/User/yourusername/Documents/Github/jamf_mcp/mcp_jamf_server.js`

    {
      "mcpServers": {
        "jamf-pro": {
          "command": "node",
          "args": [
            "~/jamf_mcp/mcp_jamf_server.js"
          ]
        }
      }
    }

Save the setting.
You will now see the jamf-pro server MCP connection.
You may need to click enable or refresh.
It will show a green dot when it connects to the mcp server.
If it shows red stil double check the path then quit Cursor and reopen.

![cursor mcp connection](https://github.com/mat-griffin/jamf-mcp/blob/main/images/cursor_mcp_connection.png)

Now in Cursor open AI chat in Agent mode enter a question to test the connection:
***"How many computers are in Jamf?"***

If Cursor starts doing odd stuff like creating code or searching the web force it to use the jamf-pro mcp by saying: *"How many computers are in Jamf? Use the jamf-pro MCP connection."*

If you get a response like:
*"Okay, I can help with that. I need your Jamf Pro username and password to get the computer counts. Could you please provide them?" 
Tel cursor "use the details in @mcp_jamf_server.js Do not display the username or password in the chat."

Cursor will respond similar to:
*"OK. I will use the credentials to get the management counts from Jamf Pro."*

On each use of the MCP query you may need to click the blue **Run Tool** to proceed. 
To stop this ensure *Cursor Enable Auto Run Mode* is ticked in *Settings > Features*

Cursor should respond with something like:

> *According to Jamf Pro: 
> There are 2000 managed computers. 
> There are 155 unmanaged computers. 
> The total number of computers is 2155.*


This screen grab shows the above
https://github.com/mat-griffin/jamf-mcp/blob/main/images/cursor_jamf_output.png




Try another query like:
***"List 5 managed computers."***

Cursor should respond with something like:

>    Here are the details:
>     ID: 3983
>     ID: 3209
>     ID: 7309
>     ID: 2440
>     ID: 2950

Now ask:
***"Show me details of 3983."*** *(enter your choice of ID from the results you got)*

You should get detailed information like this *(some items have be changed in the example below)*.

> Okay, here are the details for the computer with ID 3983:
> 
> General Information: 
> Name: C02XXXXX 
> Platform: Mac 
> Last Contact Time: 2025-04-03T13:49:34.784Z 
> Last Enrolled Date: 2024-07-09T11:07:14.769Z
> Enrollment Method: Standard User 
> Site: None 
> Hardware: 
> Model: MacBook Pro (16-inch, 2019) 
> Model Identifier: MacBookPro16,1 
> Serial Number: C02XXXXX
> Processor: Unknown (Speed: 2400 MHz, 8 Cores) 
> Memory: 32 GB 
> MAC Address: 5C:XXXXX 
> Operating System: Name: macOS Version: 15.3.2 
> Build: 24D81
> FileVault 2 Status: BOOT_ENCRYPTED 
> Gatekeeper Status: APP_STORE_AND_IDENTIFIED_DEVELOPERS
> Xprotect Version: 5292 
> Storage: Device: disk0 (APPLE SSD AP0512N)
> Size: ~500 GB Partitions: 
> Includes Macintosh HD (Boot), VM, Data, Update, Preboot (various encryption states and usage percentages)
> User: bob
> Username: bob smith 
> Email: bob.smith@somewhere.com 
> Position: User

Cursor may also respond with suggestions.

## Connection Tools
If you examine the Cursor MCP Connection in Settings > MCP you will see there are 7 tools to retrieve information.

![cursor mcp connection](https://github.com/mat-griffin/jamf-mcp/blob/main/images/cursor_mcp_connection.png)

    getComputerBySerial
    getComputerById
    listComputers
    getExtensionAttributes
    getManagementCounts
    getComputersBySerial
    getSecurityStatus

Thats it. 
As you are in Cursor use it to add more tools and fix my bugs and poor code.



