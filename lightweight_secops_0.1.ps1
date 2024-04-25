<#
program     main secops controller
programmer  zachary ostrander
#>

function New-WebRequestForIP {

    # Define output file path
    $bp = "$($env:HOMEPATH)\Downloads\data-dump"
    # Define list of refined logs
    $collection = New-Object System.Collections.Generic.List[object]
    # Token monster wants TOKENS (read input from the user to aquire ipinfo.io api token)
    $dontlookatmepleasssse = Read-Host "GIVE ME YO TOKEN, FOOL" -AsSecureString
    $plainTextTokenHeHe = ConvertFrom-SecureString -SecureString $dontlookatmepleasssse -AsPlainText
    # Import our exported csv file from the ms graph script already run and define $logs
    $logs = Import-Csv -Path "$($bp)\csv_all.csv"

    Write-Host "`n"

    $uniqueIPs = $logs.ClientIP | Sort | Get-Unique
    # Iterate logs and perform lookup on each ip
    foreach ($ip in $uniqueIPs)
    {
        # Define IOC variables for extended detection
        $countryIOC = "none"
        $regionIOC = "none"
        # Define the URL for the API
        $apiUrl = "https://ipinfo.io//$($ip)//json?token=$($plainTextTokenHeHe)"

        try {
            # Make the web request
            $response = Invoke-WebRequest -Uri $apiUrl

            # Convert the JSON response to a PowerShell object
            $ipInfo = $response.Content | ConvertFrom-Json

            if ($ipInfo.country -ne $null -and $ipInfo.country -ne "") {
                if ($ipInfo.country -ne "US") 
                { 
                    $countryIOC = "FLAG_COUNTRY"
                }
                if ($ipInfo.region -ne "Michigan") 
                { 
                    $regionIOC = "FLAG_REGION"
                }

                # Define custom powershell object
                $ipPSOBJ = New-Object PSObject -Property @{
                    IP = $ipInfo.ip
                    Region = $ipInfo.region
                    City = $ipInfo.city
                    Country = $ipInfo.country
                    Zip = $ipInfo.postal
                    LocQuard = $ipInfo.loc                                                                                          
                    Org = $ipInfo.org                                                                                      
                    Timezone = $ipInfo.timezone
                    CountryIOC = $countryIOC
                    RegionIOC = $regionIOC
                }
                $null = $collection.Add($ipPSOBJ)
            }
            else {
                $dateTimeNow = (get-date).datetime
                $errOne = "Error fetching IP entry for IP: $($ip) at $($dateTimeNow)."
                Out-File -InputObject $errOne -Encoding ASCII -Width 50 -FilePath .\errorlog.txt -Append
            }
        } 
        catch 
        {
            $err = "Error making web request at $((get-date).datetime)`n$($_)"
            Out-File -InputObject $err -Encoding ASCII -Width 50 -FilePath .\errorlog.txt -Append
        }
    }

    # Group files by extension and then sort within each group by file size
    $collection = $collection | Group-Object Region,City,Country | ForEach-Object {
        $_.Group | Sort-Object TimeStamp -Descending
    }

    $uniquesTimezones = $collection.Timezone | Get-Unique | Sort
    $uniquesRegions = $collection.Region | Get-Unique | Sort
    $uniquesCities = $collection.City | Get-Unique | Sort
    $uniquesCountries = $collection.Country | Get-Unique | Sort
    $uniquesLocQuards = $collection.LocQuard | Get-Unique | Sort
    
    Write-Host -foregroundcolor white "`tUNIQUE TIMEZONES"
    foreach ($tz in $uniquesTimezones) {
        if ($tz -ne "America/Detroit") 
        { 
            Write-Host -foregroundcolor Magenta "`t`t$($tz)"
        }
        else {
            Write-Host -foregroundcolor white "`t`t$($tz)"
        }
    }

    Write-Host -foregroundcolor white "`n`tUNIQUE REGIONS"
    foreach ($reg in $uniquesRegions) {
        if ($reg -ne "Michigan") 
        { 
            Write-Host -foregroundcolor Magenta "`t`t$($reg)"
        }
        else {
            Write-Host -foregroundcolor white "`t`t$($reg)"
        }
    }

    Write-Host -foregroundcolor white "`n`tUNIQUE CITIES"
    foreach ($city in $uniquesCities) {
        if ($city -ne "Okemos" -and $city -ne "Detroit" -and $city -ne "Farmington Hills" -and $city -ne "Dimondale" -and $city -ne "Dearborn Heights") 
        { 
            Write-Host -foregroundcolor Magenta "`t`t$($city)"
        }
        else {
            Write-Host -foregroundcolor white "`t`t$($city)"
        }
    }

    Write-Host -foregroundcolor white "`n`tUNIQUE COUNTRIES"
    foreach ($country in $uniquesCountries) {
        if ($country -ne "US" ) 
        { 
            Write-Host -foregroundcolor Magenta "`t`t$($country)"
        }
        else {
            Write-Host -foregroundcolor white "`t`t$($country)"
        }
    }

    Write-Host -foregroundcolor white "`n`tUNIQUE QUARDINATES"
    foreach ($quardinate in $uniquesLocQuards) {
        if ($quardinate -notlike "*42.*" ) 
        { 
            Write-Host -foregroundcolor Magenta "`t`t$($quardinate)"
        }
        else {
            Write-Host -foregroundcolor white "`t`t$($quardinate)"
        }
    }

    $collection | Export-Csv -Path "$($bp)\ip-enhanced_logs.csv" -NoTypeInformation
    Export-DataToHtml -Data $collection -FilePath "$($bp)\ip-metrics_report.html"

    Write-Host -foregroundcolor DarkMagenta "`nInitiating location replacements for csv_all.csv from the ip addresses we looked up with ipinfo.io."
    foreach ($ip in $collection) {
        foreach ($ipa in $logs) 
        {
            if ($ip.IP -eq $ipa.ClientIP -and $ipa.ClientIP -ne "127.0.0.1" -and $ipa.ClientIP -ne "" -and $ipa.ClientIP -ne " " -and $ipa.ClientIP -ne $null) 
            {
                $ipa.Location = "$($ip.City), $($ip.Region) $($ip.Country)" 
            }
        }
    }
    $logs | Export-Csv -Path "$($bp)\csv_all.csv" -NoTypeInformation
}
function Export-DataToHtml {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[object]]$Data,

        [string]$FilePath
    )

    # Custom CSS Styles for better aesthetics
    $customCSS = "<style>
        /* Basic Reset */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background-color: #e8eff1;
            color: #333;
            line-height: 1.6;
            padding: 20px;
        }
        .header-container {
            width: 100%;
            background-color: #2c3e50;
            padding: 20px 0;
            margin-bottom: 20px;
        }
        h1 {
            background-color: #2c3e50;
            color: #ecf0f1;
            text-align: center;
            padding: 20px 0;
            margin-bottom: 20px;
            width: 100vw; /* Sets the width to the full viewport width */
            position: relative; /* Aligns the header correctly */
            left: 50%; /* Move it to the right by half of its own width */
            right: 50%; /* Move it to the left by half of its own width */
            margin-left: -50vw; /* Negate the left offset */
            margin-right: -50vw; /* Negate the right offset */
        }

        /* Styling the table */
        table {
            width: 100%;
            margin-bottom: 20px;
            border-collapse: collapse;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
            table-layout: auto; /* Allows columns to adjust based on content */
        }

        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 2px solid #dee2e6;
            word-wrap: break-word; /* Ensures long words can wrap within a cell */
        }

        th {
            background-color: #3498db;
            color: white;
            letter-spacing: 1px;
        }

        tr:nth-child(even) {
            background-color: #f8f9fa;
        }

        tr:hover {
            background-color: #f1f1f1;
            transform: scale(1.02);
            transition: transform 0.3s ease-in-out;
        }

        /* Responsive Design */
        @media screen and (max-width: 600px) {
            table {
                width: 100%;
                display: block;
            }

            th, td {
                word-wrap: break-word;
            }
        }
    </style>"

    # Convert data to HTML with custom styles
    $htmlContent = $Data | ConvertTo-Html -Head $customCSS # -PreContent "<h1>Report</h1>" -PostContent "<h2>End of Report</h2>"
    $htmlContent | Out-File $FilePath
}
function Set-ClientAzADSignInInteractiveMetrics {
    param(
    [string]$clientIP, 
    [DateTime]$loginTime,
    [string]$location
    )
        try {
            # check if the ip address is already in our hashtable (as we do not want duplicates.)
            if ($clientIPMetricsAzADIntHT.ContainsKey($clientIP)) {

                # increment count
                $clientIPMetricsAzADIntHT[$clientIP].Count++

                # set earliest and latest login times
                if ($loginTime -le $clientIPMetricsAzADIntHT[$clientIP].EarliestLogin) {
                    $clientIPMetricsAzADIntHT[$clientIP].EarliestLogin = $loginTime
                }

                if ($loginTime -ge $clientIPMetricsAzADIntHT[$clientIP].LatestLogin) {
                    $clientIPMetricsAzADIntHT[$clientIP].LatestLogin = $loginTime
                } 

                $clientIPMetricsAzADIntHT[$clientIP].Location = $location
            }
            # add new item to our hashtable if not already inside
            else {
                $clientIPMetricsAzADIntHT[$clientIP] = @{
                    Count           = 1
                    EarliestLogin   = $loginTime
                    LatestLogin     = $loginTime
                    ClientIPAdd     = $clientIP
                    Location        = $location
                }
            }
        }
        # catch exceptions
        catch {
            Write-Host -foregroundcolor white "new key likely created, see error below in case not so."; Write-Host -foregroundcolor white "$($_)"
        }
}
function Set-ClientAzADSignInNonInteractiveMetrics {
    param(
        [string]$clientIP, [DateTime]$loginTime,
        [string]$location
    )
    try {
        # check if the ip address is already in our hashtable (as we do not want duplicates.)
        if ($clientIPMetricsAzADNonIntHT.ContainsKey($clientIP)) {

            # increment count
            $clientIPMetricsAzADNonIntHT[$clientIP].Count++

            # set earliest and latest login times
            if ($loginTime -le $clientIPMetricsAzADNonIntHT[$clientIP].EarliestLogin) {
                $clientIPMetricsAzADNonIntHT[$clientIP].EarliestLogin = $loginTime
            }

            if ($loginTime -ge $clientIPMetricsAzADNonIntHT[$clientIP].LatestLogin) {
                $clientIPMetricsAzADNonIntHT[$clientIP].LatestLogin = $loginTime
            } 

            $clientIPMetricsAzADNonIntHT[$clientIP].Location = $location
        }
        # add new item to our hashtable if not already inside
        else {
            $clientIPMetricsAzADNonIntHT[$clientIP] = @{
                Count           = 1
                EarliestLogin   = $loginTime
                LatestLogin     = $loginTime
                ClientIPAdd     = $clientIP
                Location        = $location
            }
        }
    }
    # catch exceptions
    catch {
        Write-Host -foregroundcolor white "new key likely created, see error below in case not so."; Write-Host -foregroundcolor white "$($_)"
    }
}
function Set-ClientComplianceMetrics {
    param(
        [string]$clientIP, 
        [DateTime]$loginTime
    )
    try {
        # check if the ip address is already in our hashtable (as we do not want duplicates.)
        if ($clientIPMetricsCompHT.ContainsKey($clientIP)) {
            # increment count
            $clientIPMetricsCompHT[$clientIP].Count++
            # set earliest and latest login times
            if ($loginTime -le $clientIPMetricsCompHT[$clientIP].EarliestLogin) {
                $clientIPMetricsCompHT[$clientIP].EarliestLogin = $loginTime
            }
            if ($loginTime -ge $clientIPMetricsCompHT[$clientIP].LatestLogin) {
                $clientIPMetricsCompHT[$clientIP].LatestLogin = $loginTime
            } 
        }
        # add new item to our hashtable if not already inside
        else {
            $clientIPMetricsCompHT[$clientIP] = @{
                Count           = 1
                EarliestLogin   = $loginTime
                LatestLogin     = $loginTime
                ClientIPAdd     = $clientIP
            }
        }
    }
    # catch exceptions
    catch {
        Write-Host -foregroundcolor Green "new key likely created, see error below in case not so."; Write-Host "$($_)"
    }
}
function Set-ClientMailboxMetrics {

    param(
        [string]$clientIP, [DateTime]$loginTime
    )

    try {
        # check if the ip address is already in our hashtable (as we do not want duplicates.)
        if ($clientIPMetricsMailboxHT.ContainsKey($clientIP)) {

            # increment count
            $clientIPMetricsMailboxHT[$clientIP].Count++

            # set earliest and latest login times
            if ($loginTime -le $clientIPMetricsMailboxHT[$clientIP].EarliestLogin) {
                $clientIPMetricsMailboxHT[$clientIP].EarliestLogin = $loginTime
            }

            if ($loginTime -ge $clientIPMetricsMailboxHT[$clientIP].LatestLogin) {
                $clientIPMetricsMailboxHT[$clientIP].LatestLogin = $loginTime
            } 
        }
        # add new item to our hashtable if not already inside
        else {
            $clientIPMetricsMailboxHT[$clientIP] = @{
                Count           = 1
                EarliestLogin   = $loginTime
                LatestLogin     = $loginTime
                ClientIPAdd     = $clientIP
            }
        }
    }
    # catch exceptions
    catch {
        Write-Host -foregroundcolor white "new key likely created, see error below in case not so."; Write-Host -foregroundcolor white "$($_)"
    }
}
function Import-Mailbox {
    # set a base path so we do not need to type it out a ton of times. 
    $ogPath = "$($env:HOMEPATH)\Downloads"
    $basePath = "$($env:HOMEPATH)\Downloads\data-dump"

    $csvMailboxAL = Import-Csv -Path "$ogPath\Mailbox Audit Log.csv"

    $clientIPMetricsMailboxHT = @{}
    $ipArrMail = @() 
    $dataArrMail = @() 
    $dataCountMail = 0  

    # for each row in the csv file... perform the following operations...
    foreach ($row in $csvMailboxAL) {

        $dataCountMail++

        # call special ip function to collect metric information for this row currently being iterated
        Set-ClientMailboxMetrics "$($row.ClientIP)" $row.LastAccessed

        # create custom powershell object 
        $customObj = [PSCustomObject]@{
            ClientIP        = $row.ClientIP
            Location        = ""
            TimeStamp       = $row.LastAccessed
            StdDev          = $null
            Operation       = $row.Operation
            FolderPath      = $row.FolderPathName
            DestFolderPath  = $row.DestFolderPathName
            SrcItemFoldPath = $row.SourceItemFolderPathNamesList
            ResultStatus    = $row.OperationResult
            ClientProcess   = $row.ClientProcessName
            AffectedItems   = $row.Path
            InternalLogonType = $row.InternalLogonType
            LogonType       = $row.LogonType
            Subject         = $row.ItemSubject
            SourceItemSub   = $row.SourceItemSubjectsList
            Attachments     = $row.ItemAttachments
            SrcItemAttach   = $row.SourceItemAttachmentsList
            ClientString    = $row.ClientInfoString
            Count           = $dataCountMail
        }

        # add custom object to our array - later on we will export the array of objects to csv 
        $dataArrMail += $customObj
    }

    # convert hashtable to custom powershell object
    foreach ($clientIPAddr in $clientIPMetricsMailboxHT.Keys) {

        # create custom powershell object 
        $customObj = [PSCustomObject]@{
            ClientIP    = $clientIPMetricsMailboxHT[$clientIPAddr].ClientIPAdd
            IpCount       = $clientIPMetricsMailboxHT[$clientIPAddr].Count
            EarlyLogin  = $clientIPMetricsMailboxHT[$clientIPAddr].EarliestLogin
            LateLogin   = $clientIPMetricsMailboxHT[$clientIPAddr].LatestLogin
            Log         = "Mail"
            Location    = ""
        }
        # add custom object to our array - later on we will export the array of objects to csv 
        $ipArrMail += $customObj
    }

    # Group files by extension and then sort within each group by file size
    $sortedDataArrMail = $dataArrMail | Group-Object ClientIP | ForEach-Object {
        $_.Group | Sort-Object TimeStamp -Descending
    }

    $ipArrMail | Sort ClientIP | Export-Csv -Path "$basePath\export-ip_metrics\csv_ip-metrics-mail.csv" -NotypeInformation
    $dataArrMail | Sort TimeStamp | Export-Csv -Path "$basePath\export-normalized\csv_normalized_mailbox.csv" -NotypeInformation

    Export-DataToHtml -Data $dataArrMail -FilePath "$($basePath)\export-html\mailbox_report.html"
    Export-DataToHtml -Data $sortedDataArrMail -FilePath "$($basePath)\export-html\mailboxsorted_report.html"
}
function Import-SignIn {
    # set a base path so we do not need to type it out a ton of times. 
    $ogPath = "$($env:HOMEPATH)\Downloads"
    $basePath = "$($env:HOMEPATH)\Downloads\data-dump"
    $csvInteractiveAL= Import-Csv -Path "$ogPath\InteractiveSignIns.csv"
    $csvNonInteractiveAL = Import-Csv -Path "$ogPath\NonInteractiveSignIns.csv"
    $clientIPMetricsAzADIntHT = @{}
    $clientIPMetricsAzADNonIntHT = @{}
    $dataArrInt = @() 
    $ipArrAzAdNonInt = @()
    $dataArrNonInt = @() 
    $ipArrAzAdInt = @() 
    $dataCountInt = 0   # int - counter variable
    $dataCountNonInt = 0   # int - counter variable

    # for each row in the csv file... create variables to be passed to a new custom powershell object which is added to an array (for each row)
    foreach ($row in $csvInteractiveAL) {

        $dataCountInt++
        
        Set-ClientAzADSignInInteractiveMetrics "$($row."IP address")" $row."Date (UTC)" "$($row.Location)"

        # create custom powershell object 
        $customObj = [PSCustomObject]@{
            ClientIP        = $row."IP address"
            Location        = $row.Location
            TimeStamp       = $row."Date (UTC)"
            StdDev          = $null
            Operation       = "AzAD Sign-In Attempt"
            ResultStatus    = $row.Status
            Application     = $row.Application
            Resource        = $row.Resource
            Browser         = $row.Browser
            ClientApp       = $row."Client app"
            AZADJoinType    = $row."Join Type"
            OperatingSystem = $row."Operating System"
            AuthRequirement = $row."Authentication requirement"
            ConditAccess    = $row."Conditional Access"
            MultifactorAuthenticationResult = $row."Multifactor authentication result"
            AuthenticationFailureReasoning = $row."Failure Reason"
            Count           = $dataCountInt
        }
        $dataArrInt += $customObj
    }
    foreach ($row in $csvNonInteractiveAL) {
        $dataCountNonInt++

        Set-ClientAzADSignInNonInteractiveMetrics "$($row."IP address")" $row."Date (UTC)" "$($row.Location)"

        # create custom powershell object 
        $customObj = [PSCustomObject]@{
            ClientIP        = $row."IP address"
            Location        = $row.Location
            TimeStamp       = $row."Date (UTC)"
            StdDev          = $null
            Operation       = "AzAD Non-Int Sign-In Attempt"
            ResultStatus    = $row.Status
            Application     = $row.Application
            Resource        = $row.Resource
            Browser         = $row.Browser
            ClientApp       = $row."Client app"
            AZADJoinType    = $row."Join Type"
            OperatingSystem = $row."Operating System"
            AuthRequirement = $row."Authentication requirement"
            ConditAccess    = $row."Conditional Access"
            MultifactorAuthenticationResult = $row."Multifactor authentication result"
            AuthenticationFailureReasoning = $row."Failure Reason"
            Count           = $dataCountNonInt
        }
        $dataArrNonInt += $customObj
    }

    # convert hashtable to custom powershell object
    foreach ($clientIPAddr in $clientIPMetricsAzADIntHT.Keys) {

        # create custom powershell object 
        $customObj = [PSCustomObject]@{
            ClientIP    = $clientIPMetricsAzADIntHT[$clientIPAddr].ClientIPAdd
            IpCount       = $clientIPMetricsAzADIntHT[$clientIPAddr].Count
            EarlyLogin  = $clientIPMetricsAzADIntHT[$clientIPAddr].EarliestLogin
            LateLogin   = $clientIPMetricsAzADIntHT[$clientIPAddr].LatestLogin
            Log         = "Int Login"
            Location    = $clientIPMetricsAzADIntHT[$clientIPAddr].Location
        }
        # add custom object to our array - later on we will export the array of objects to csv 
        $ipArrAzAdInt += $customObj
    }
    # convert hashtable to custom powershell object
    foreach ($clientIPAddr in $clientIPMetricsAzADNonIntHT.Keys) {

        # create custom powershell object 
        $customObj = [PSCustomObject]@{
            ClientIP    = $clientIPMetricsAzADNonIntHT[$clientIPAddr].ClientIPAdd
            IpCount       = $clientIPMetricsAzADNonIntHT[$clientIPAddr].Count
            EarlyLogin  = $clientIPMetricsAzADNonIntHT[$clientIPAddr].EarliestLogin
            LateLogin   = $clientIPMetricsAzADNonIntHT[$clientIPAddr].LatestLogin
            Log         = "NonInt Login"
            Location    = $clientIPMetricsAzADNonIntHT[$clientIPAddr].Location
        }
        # add custom object to our array - later on we will export the array of objects to csv 
        $ipArrAzAdNonInt += $customObj
    }

    # Group files by extension and then sort within each group by file size
    $sortedDataArrIntSignin = $dataArrInt | Group-Object ClientIP | ForEach-Object {
        $_.Group | Sort-Object TimeStamp -Descending
    }
    # Group files by extension and then sort within each group by file size
    $sortedDataArrNonIntSignIn = $dataArrNonInt | Group-Object ClientIP | ForEach-Object {
        $_.Group | Sort-Object TimeStamp -Descending
    }

    $ipArrAzAdInt | Sort ClientIP | Export-Csv -Path "$basePath\export-ip_metrics\csv_ip-metrics-azad-int.csv" -NotypeInformation
    $ipArrAzAdNonInt | Sort ClientIP | Export-Csv -Path "$basePath\export-ip_metrics\csv_ip-metrics-azad-nonint.csv" -NotypeInformation
    $dataArrInt | Sort TimeStamp | Export-Csv -Path "$basePath\export-normalized\csv_normalized_int_signin.csv" -NotypeInformation
    $dataArrNonInt | Sort TimeStamp | Export-Csv -Path "$basePath\export-normalized\csv_normalized_non-int_signin.csv" -NotypeInformation

    Export-DataToHtml -Data $dataArrInt -FilePath "$($basePath)\export-html\interactive_report.html"
    Export-DataToHtml -Data $dataArrNonInt -FilePath "$($basePath)\export-html\non-interactive_report.html"
    Export-DataToHtml -Data $sortedDataArrIntSignin -FilePath "$($basePath)\export-html\intsigninsorted_report.html"
    Export-DataToHtml -Data $sortedDataArrNonIntSignIn -FilePath "$($basePath)\export-html\nonintsigninsorted_report.html"
}
function Import-Compliance {

    # set a base path so we do not need to type it out a ton of times. 
    $ogPath = "$($env:HOMEPATH)\Downloads"
    $basePath = "$($env:HOMEPATH)\Downloads\data-dump"

    # hashtables - used for key iteration when setting special custom metrics
    $clientIPMetricsCompHT = @{} 

    # arrays - used for object iteration/storage
    $dataArrComp    = @() 
    $ipArrCom       = @() 
    $dataCountComp  = 0   

    # soak up the comma seperated values (csv file) and assign to variables so we can iterate each row from each csv file
    $csvComplianceAL = Import-Csv -Path "$ogPath\Compliance Audit Log.csv"

    # for each row in the csv file... create variables to be passed to a new custom powershell object which is added to an array (for each row)
    foreach ($row in $csvComplianceAL) {

        $dataCountComp++

        # expand the shit AuditData column from the compliance audit export (csv file)
        $auditData = $row.AuditData | ConvertFrom-Json

        # call special ip function to collect metric information for this row currently being iterated
        Set-ClientComplianceMetrics "$($auditData.ClientIP)" $auditData.CreationTime

        # create custom powershell object 
        $customObjNormalizedCompliance = [PSCustomObject]@{
            ClientIP        = $auditData.ClientIP
            Location        = ""
            DateTimeUTC     = $auditData.CreationTime
            StdDev          = $null
            Operation       = $row.Operation
            ResultStatus    = $auditData.ResultStatus
            UserAgent       = $auditData.UserAgent
            EventSource     = $auditData.EventSource
            Workload        = $auditData.Workload
            ClientInfoString= $auditData.ClientInfoString
            ClientProcess   = $auditData.ClientProcessName
            ClientVersion   = $auditData.ClientVersion
            AffectedItems   = $auditData.Path
            LogonType       = $auditData.LogonType
            Subject         = $auditData.Item.Subject
            UserKey         = $auditData.UserKey # item unique to compliance audit
            Attachments     = $auditData.Item.Attachments
            Count           = $dataCountComp
            UserId          = $auditData.UserId
            SourceFileName  = $auditData.SourceFileName
            SiteURL         = $auditData.SiteUrl
            ObjectID        = $auditData.ObjectId
            Platform        = $auditData.Platform
            RuleName        = $auditData.OperationProperties.RuleName.Value
            RuleOperation   = $auditData.OperationProperties.RuleOperation.Value
            RuleCondition   = $auditData.OperationProperties.RuleCondition.Value
            RuleActions     = $auditData.OperationProperties.RuleActions.Value
        }
        # add custom object to our array - later on we will export the array of objects to csv 
        $dataArrComp += $customObjNormalizedCompliance
    }

    # convert hashtable to custom powershell object
    foreach ($clientIPAddr in $clientIPMetricsCompHT.Keys) {

        # create custom powershell object 
        $customObj = [PSCustomObject]@{
            ClientIP    = $clientIPMetricsCompHT[$clientIPAddr].ClientIPAdd
            IpCount       = $clientIPMetricsCompHT[$clientIPAddr].Count
            EarlyLogin  = $clientIPMetricsCompHT[$clientIPAddr].EarliestLogin
            LateLogin   = $clientIPMetricsCompHT[$clientIPAddr].LatestLogin
            Log         = "Comp"
            Location    = ""
        }
        # add custom object to our array - later on we will export the array of objects to csv 
        $ipArrCom += $customObj
    }

    $ipArrCom | Sort ClientIP | Export-Csv -Path "$basePath\export-ip_metrics\csv_ip-metrics-comp.csv" -NotypeInformation
    $dataArrComp | Sort TimeStamp | Export-Csv -Path "$basePath\export-normalized\csv_normalized_compliance.csv" -NotypeInformation

    # Group files by extension and then sort within each group by file size
    $sortedDataArrComp = $dataArrComp | Group-Object ClientIP | ForEach-Object {
        $_.Group | Sort-Object DateTimeUTC -Descending
    }

    # Display the sorted files
    Export-DataToHtml -Data $sortedDataArrComp -FilePath "$($basePath)\export-html\compliancesorted_report.html"
    Export-DataToHtml -Data $dataArrComp -FilePath "$($basePath)\export-html\compliance_report.html"
}
function New-DumpFile {
    # set base paths so we do not need to type them out a ton of times and can easily modify in one spot.
    $ogPath = "$($env:HOMEPATH)\Downloads"

    $basePath = "$($ogPath)\data-dump"
    $basePathHtml = "$($ogPath)\data-dump\export-html"
    $basePathIPMetrics = "$($ogPath)\data-dump\export-ip_metrics"
    $basePathNormalized = "$($ogPath)\data-dump\export-normalized"


    if (Test-Path -Path "$($basePath)") {}
    else 
    { 
        New-Item -Name "data-dump" -ItemType "directory" -Path "$($ogPath)" > $null
    }

    if (Test-Path -Path "$($basePathHtml)") {}
    else 
    { 
        New-Item -Name "export-html" -ItemType "directory" -Path "$($basePath)" > $null
    }

    if (Test-Path -Path "$($basePathNormalized)") {}
    else 
    { 
        New-Item -Name "export-normalized" -ItemType "directory" -Path "$($basePath)" > $null
    }

    if (Test-Path -Path "$($basePathIPMetrics)") {}
    else 
    { 
        New-Item -Name "export-ip_metrics" -ItemType "directory" -Path "$($basePath)" > $null
    }
}
function Merge-Logs {

    # set a base path to use throughout the script
    $basePath = "$($env:HOMEPATH)\Downloads\data-dump"

    # import csv files from the the ip metrics we already ran in the import-<logname>.ps1 scripts. we will use them to create a log with all the entries in one spot. 
    $ipArrCom = Import-Csv -Path "$basePath\export-ip_metrics\csv_ip-metrics-comp.csv"
    $ipArrMail = Import-Csv -Path "$basePath\export-ip_metrics\csv_ip-metrics-mail.csv"
    $ipArrAzAdInt = Import-Csv -Path "$basePath\export-ip_metrics\csv_ip-metrics-azad-int.csv"
    $ipArrAzAdNonInt = Import-Csv -Path "$basePath\export-ip_metrics\csv_ip-metrics-azad-nonint.csv"

    $normArrCom = Import-Csv -Path "$basePath\export-normalized\csv_normalized_compliance.csv"
    $normArrMail = Import-Csv -Path "$basePath\export-normalized\csv_normalized_mailbox.csv"

    # apply locations from interactive and non interactoive to mailbox and complaince ip metrics
    foreach ($ip in $ipArrAzAdNonInt) {
        foreach ($ipComp in $ipArrCom) 
        {
            if ($ip.ClientIP -eq $ipComp.ClientIP) 
            {
                $ipComp.Location = $ip.Location
            }
        }
        foreach ($ipMail in $ipArrMail) 
        {
            if ($ip.ClientIP -eq $ipMail.ClientIP) 
            {
                $ipMail.Location = $ip.Location
            }
        }
        foreach ($normCom in $normArrCom) 
        {
            if ($ip.ClientIP -eq $normCom.ClientIP) 
            {
                $normCom.Location = $ip.Location
            }
        }
        foreach ($normMail in $normArrMail) 
        {
            if ($ip.ClientIP -eq $normMail.ClientIP) 
            {
                $normMail.Location = $ip.Location
            }
        }
    }
    foreach ($ip in $ipArrAzAdInt) {
        foreach ($ipComp in $ipArrCom) 
        {
            if ($ip.ClientIP -eq $ipComp.ClientIP) 
            {
                $ipComp.Location = $ip.Location
            }
        }
        foreach ($ipMail in $ipArrMail) 
        {
            if ($ip.ClientIP -eq $ipMail.ClientIP) 
            {
                $ipMail.Location = $ip.Location
            }
        }
        foreach ($normCom in $normArrCom) 
        {
            if ($ip.ClientIP -eq $normCom.ClientIP) 
            {
                $normCom.Location = $ip.Location
            }
        }
        foreach ($normMail in $normArrMail) 
        {
            if ($ip.ClientIP -eq $normMail.ClientIP) 
            {
                $normMail.Location = $ip.Location
            }
        }
    }

    # combine the logs - this only works because the objects in the ip metric arrays have the same properties (so columns match)
    $ipArrAll = $ipArrCom + $ipArrMail + $ipArrAzAdInt + $ipArrAzAdNonInt
    $ipArrAll = $ipArrAll | Group-Object ClientIP | ForEach-Object {
        $_.Group | Sort-Object EarlyLogin -Descending
    }
    Export-DataToHtml -Data $ipArrAll -FilePath "$($basePath)\ip-metrics_report.html"

    # export the logs with added location value to csv file 
    $ipArrCom | Export-Csv -Path "$basePath\export-ip_metrics\csv_ip-metrics-comp.csv" -NotypeInformation
    $ipArrMail | Export-Csv -Path "$basePath\export-ip_metrics\csv_ip-metrics-mail.csv" -NotypeInformation
    $ipArrAzAdInt | Export-Csv -Path "$basePath\export-ip_metrics\csv_ip-metrics-azad-int.csv" -NotypeInformation
    $ipArrAzAdNonInt | Export-Csv -Path "$basePath\export-ip_metrics\csv_ip-metrics-azad-nonint.csv" -NotypeInformation

    # export the 'mega log' to csv file 
    $ipArrAll | Export-Csv -Path "$basePath\csv_all.csv" -NotypeInformation
}
function Remove-ExtraFiles {
    $basePath = "$($env:HOMEPATH)\Downloads\data-dump"
    $fileType = '*.txt'
    $keepFilesArray = @("stats.txt")
    $files = Get-ChildItem -Path $basePath -Filter $fileType #-Recurse
    foreach ($file in $files) 
    {
        if ($file -like '*.txt')
        {
            if ($keepFilesArray -notcontains $file.Name)
            {
                Write-Host -foregroundcolor white "`tdeleting text file $($file.FullName)"
                Remove-Item $file.FullName -Force
            }
        }
    }
}

# Create a stopwatch
$stopwatch = New-Object System.Diagnostics.Stopwatch
$stopwatch.Start()
$count = 0
$keepGoing = $true
# Maximum runtime in seconds (5 minutes)
$maxRuntime = 60
while ($keepGoing) {
    # Wait for the script to finish or max runtime to be reached
    do {
        Start-Sleep -Seconds 1
        $count++
        if ($count -ge 7) { $keepGoing = $false}
        switch ($count) {
            1 {
                clear
                Write-Host -foregroundcolor DarkMagenta "`nCreating your report's folder structure."
                New-DumpFile
                Write-Host -foregroundcolor white "`tFinished creating export folder structure.`n"
                break
            }
            2 {
                Write-Host -foregroundcolor DarkMagenta "Importing your compliance audit log."
                Import-Compliance
                Write-Host -foregroundcolor white "`tFinished importing your compliance audit log.`n"
                break
            }
            3 {
                Write-Host -foregroundcolor DarkMagenta "Importing your mailbox audit log."
                Import-Mailbox
                Write-Host -foregroundcolor white "`tFinished importing your mailbox audit log.`n"
                break
            }
            4 {
                Write-Host -foregroundcolor DarkMagenta "Importing your sign-in audit log."
                Import-SignIn
                Write-Host -foregroundcolor white "`tFinished importing your sign-in audit logs.`n"
                break
            }
            5 {
                Write-Host -foregroundcolor DarkMagenta "Merging logs."
                Merge-Logs
                Write-Host -foregroundcolor white "`tFinished merging logs.`n"
                break
            }
            6 {
                Write-Host -foregroundcolor DarkMagenta "Removing any extra files."
                Remove-ExtraFiles
                Write-Host -foregroundcolor white "`tFinished removing any extra files.`n"
                break
            }
            7 {
                Write-Host -foregroundcolor DarkMagenta "Validating IP location and ISP data."
                New-WebRequestForIP
                Write-Host -foregroundcolor white "`tFinished validating IP location and ISP data.`n"
            }
            default {
                Write-Host -foregroundcolor DarkMagenta "Execution complete. If you had issues please contact a developer.`n`n"
            }
        }

        if ($stopwatch.Elapsed.TotalSeconds -ge $maxRuntime) {
            Write-Host -foregroundcolor white "`nTime's up, let's wrap this up!`n"
            break
        }

        $remainingTime = $maxRuntime - $stopwatch.Elapsed.TotalSeconds
        Write-Progress -Activity "Running" -Status "Creating backend files, importing csv files, and running analysis... $([math]::Round($remainingTime, 2)) seconds" -PercentComplete (($stopwatch.Elapsed.TotalSeconds / $maxRuntime) * 100)

    } while (($job.State -eq 'Running') -and ($stopwatch.Elapsed.TotalSeconds -lt $maxRuntime) )
}

$stopwatch.Stop()
Write-Progress -Activity "Running scripts" -Status "Completed" -Completed