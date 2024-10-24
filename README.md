# Site Warmup
Warms up a website after deployment. Features the ability to take multiple environment configurations (e.g., dev/test/prod/etc), handle Auth0 forms authentication, uses a file with a list of URL's, simple test patterns, and the ability to use sesssion or not. The script does not currently handle Javascript, so dynamic client side redered content can not be tested.

## Status
I no longer user or maintaint this project, as we have switched to using playwright. 

## Usage
### Configuration
#### Environments
You can configure your environments using the config.json file. The JSON schema environment descriptions under a key which is the environment name. You can use one or all of them. Each environment description consists of the following fields:
- site_user - user name used to login.
- site_pass - password used to login. Usually you will leave this blank, and supply on command line to avoid storing the password in source control.
- results_dir - if specified the HTML pulled from each test URL will be stored in this directoy.
- input - name of the file which contains the list of URLs.
- domain - the root domain to test each URL againts.
- auth0_tenant - auth0 domain to autheticate against.
- tenant - if you have a multi-tenant application which requires a user to select a tenant to log into, supply it here. This is not the auth0 tenant. Most sites will not have this, but the project which this script was created for did, that is why it exists. (i.e., ignore this argument).

Here is a sample config.json
```
{
    "local": {
        "site_user": "sam@yahoo.com",
        "site_pass": "xxx",
        "results_dir": "results",
        "input": "local_warmup_list.txt",
        "domain": "http://localhost:17257",
        "auth0_tenant": "testing-test2",
        "tenant": "duff"
    },
    "dev": {
        "domain": "https://dev.duff.net",
        "site_user": "sam@yahoo.com",
        "input": "prod_warmup_list.txt",
        "auth0_tenant": "dev-test2",
        "tenant": "duff"
    }
}
```

#### URL test list
This file is of any name you want. You must specify the path to this file in the input field of your config.json.

This file consists of 3 columns seperated by a bar: `URL|test pattern|no-session flag`
- the *URL* is a path relative to the domains specified in the config file.
- the *test-pattern* is a peice of text that the script will verify exists on the page. Note that dynamicly rendered text (i.e, from react or Angular) can not be tested, as JS is not executed when the URL is loaded.
- *no session flag* is either blank, or exactly `no-session`. This tells the script to not use the authenticated session when loading the page. The reason for this is that you may want to test a certain page that can cause a session to end, which would mean your initial session is no longer valid to test other pages.
- Blank lines are ignored
- Line starting with a hash (#) are ignored.
 
 Here is an example file:
 ```
 #URL|Test pattern|no-session-flag
#comments and blank lines are allowed
AdminUsers|Manage Users
Home/Dashboard|Dashboard
InvalidSessionError|Error has occurred|no-session
 ```
 
 ### Command line
 The script is meant to be executed on the powershell command line. It takes 3 arguments:
 - ConfigFile - path to the config.json file.
 - Env - name of the environment file (the key used in the config file)
 - Password - the password to use for the site authentication. This overrides what is found in the config file.

 ### How we use it
 We run this script in our CI tool after each site deployment. We store the password in the CI tool so it is not checked into source control.
 
 ## Disclaimer
 I maintain this script for our projects, and don't currently have the time to make the script fully generic for use with other authentication forms. But feel free to contribute to get the script more robust.
