<#
.SYNOPSIS
    create DLP policies and associated DLP rules that will append text to the subject of emails sent based on the sensitivity label selected for the email.

.DESCRIPTION
    To run this script you will need to have the following information
    
    1. A naming convention for the DLP policies/rules
    2. Already have deployed sensitivity labels and published them to users
    3. The "name" of your labels, you can use get-label | select name, displayname to get this info.
        3.1 adding the display name helps you identify the correct "name" value if you are using GUIDS for the label name
        3.2 The name value is used as the variable $label when creating the DLP rule.
    4. An naming convention for the text to be appended to email subjects
        4.1 don't for get to add a space before the name otherwise it looks bad.
            4.1.1 bad: "Some subject[SEC=PUBLIC]"
            4.1.2 Better: "Some Subject [SEC=PUBLIC]"
    5. A regex that can detect the subject text to perform the replacemenet
        5.1 example subject text: [SEC=PUBLIC]
        5.2 exmaple regex: "{\[SEC=.*?\]}"
        5.3 The above regex will work with any text as long as it is fortmatted [SEC=SOME TEXT]
    6. Make sure you update all variables to match with your organisation needs / naming conventions

.PARAMETER label
    label name - "get-label | select name, displayname" 
        displayname is included incase you use GUIDS as the "NAME" value for ease of use

.PARAMETER DlpPolicyName
    Name for the DLP Policy - must be unique name for DLP policies in org will append $label to the text
        example: -DlpPolicyName "subject append" will be "subject append GENERAL" if -label = "GENERAL"

.PARAMETER DlpRuleName
    Name for the DLP rule -  must be unique name for DLP Rule name in org will append $label to the text
        example: -DlpRuleName "subject append rule" will be "subject append rule GENERAL" if -label = "GENERAL"

.PARAMETER SubjectText
    the text that i appended to the subject of emails. 

.PARAMETER Mode
    The Mode parameter specifies the action and notification level of the DLP policy. Valid values are:
       
        Enable: The policy is enabled for actions and notifications. This is the default value.
        Disable: The policy is disabled.
        TestWithNotifications: Simulation mode where no actions are taken, but notifications are sent.
        TestWithoutNotifications: Simulation mode where no actions are taken, and no notifications are sent.

.PARAMETER RegEx
    Regex used for the text replacement

.PARAMETER Comment
    Optional - Text description for your DLP Policy will append the $label variable to end of text
        example: -comment "subject append" will be "subject append GENERAL" if -label = "GENERAL"

.EXAMPLE
    Create DLP policy with "enable" mode EXCLUDING a description (comment)
     
     ./SubjectAppendDLPRule.ps1 -label "0cd28c22-0f86-4e5d-8a01-f9eb7842a452" -DlpPolicyName "subject append" -DlpRuleName "subject append rule"  -SubjectText " [SEC=GENERAL]" -Mode "enable" -RegEx "{\[SC=.*?\]}"
   

     Create DLP policy with "TestWithNotifications" mode INCLUDING a description (comment)
     
     ./SubjectAppendDLPRule.ps1 -label "0cd28c22-0f86-4e5d-8a01-f9eb7842a452" -DlpPolicyName "subject append" -DlpRuleName "subject append rule"  -SubjectText " [SEC=GENERAL]" -Mode "TestWithNotifications" -RegEx "{\[SC=.*?\]}" -comment "append subject text for"
   
     .NOTES
    Additional information about the script
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [string[]]$Label,
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [string[]]$DlpPolicyName,
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [string[]]$DlpRuleName,
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [string[]]$SubjectText,
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [string[]]$Mode,
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [string[]]$RegEx,
    [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
    [string[]]$Comment

    

    )

if($comment -eq $null) {$CommentText = ''} else {$CommentText = "$comment $label"} 
$DlpPolicyNameText = "$DlpPolicyName $label"
$DlpRuleNameText = "$DlpRuleName $label"

Write-host "Connecting to SCC with browser based authentication, user account must have required permissions"

Connect-IPPSSession -ShowBanner:$false


Write-host "Creating DLP Policy $DlpPolicyNameText"


$policy = New-DlpCompliancePolicy `
    -Name "$DlpPolicyNameText" `
    -ExchangeLocation "All" `
    -Mode "$mode" `
    -comment "$CommentText"


$complexSensitiveInformationRule = @(
    @{
        operator = "And"
        groups = @(
            @{
                operator="Or"
                name="Default"
                labels = @(
                    @{
                        name="$($label)";
                        type="Sensitivity"
                    } 
                )
            }
        )
    }
)

# Build the second complex PswsHashtable to perform the rewrite
$complexModifySubjectRule = @{
    patterns = $RegEx
    ReplaceStrategy = 'Append'
    SubjectText = "$SubjectText"
}

Write-host "Creating DLP Rule $DlpPolicyNameText"
# Create the policy
New-DlpComplianceRule `
    -Name "$DlpRuleNameText" `
    -Policy "$DlpPolicyNameText" `
    -ContentContainsSensitiveInformation $complexSensitiveInformationRule `
    -ModifySubject $complexModifySubjectRule

Write-host "Closing connection to SCC"

Disconnect-ExchangeOnline -Confirm:$false

   


