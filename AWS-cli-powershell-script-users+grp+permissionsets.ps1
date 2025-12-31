# ---------------------------------------
# Fetch SSO Instance Info
# ---------------------------------------

$ssoInstance = aws sso-admin list-instances --query "Instances[0]" | ConvertFrom-Json
$instanceArn = $ssoInstance.InstanceArn
$identityStoreId = $ssoInstance.IdentityStoreId

Write-Host "Using Instance ARN: $instanceArn"
Write-Host "Using Identity Store ID: $identityStoreId"
Write-Host "---------------------------------------------------"

# ---------------------------------------
# Fetch all SSO Groups
# ---------------------------------------

$groups = aws identitystore list-groups `
    --identity-store-id $identityStoreId `
    --query "Groups[*]" | ConvertFrom-Json

# ---------------------------------------
# Build Group -> Users mapping
# ---------------------------------------

$groupUsersMap = @{}

foreach ($group in $groups) {

    $memberships = aws identitystore list-group-memberships `
        --identity-store-id $identityStoreId `
        --group-id $group.GroupId `
        --query "GroupMemberships[*]" | ConvertFrom-Json

    $userNames = @()
    $userDisplayNames = @()
    $userEmails = @()
    $userStatuses = @()

    foreach ($membership in $memberships) {

        # Fetch user details
        $user = aws identitystore describe-user `
            --identity-store-id $identityStoreId `
            --user-id $membership.MemberId.UserId `
            --query "{ 
                        UserName:UserName, 
                        DisplayName:DisplayName, 
                        Email:Emails[0].Value,
                        Status:AccountStatus.Status
                     }" | ConvertFrom-Json

        $userNames += $user.UserName
        $userDisplayNames += $user.DisplayName
        $userEmails += $user.Email
        $userStatuses += $user.Status
    }

    # Store in map
    $groupUsersMap[$group.GroupId] = [PSCustomObject]@{
        UserNames        = ($userNames -join "; ")
        UserDisplayNames = ($userDisplayNames -join "; ")
        UserEmails       = ($userEmails -join "; ")
        UserStatuses     = ($userStatuses -join "; ")
    }
}

# ---------------------------------------
# Fetch Permission Sets + Managed Policies + Session Duration
# ---------------------------------------

$permissionSetArns = aws sso-admin list-permission-sets `
    --instance-arn $instanceArn `
    --query "PermissionSets[]" | ConvertFrom-Json

$permissionSets = @{}
foreach ($psArn in $permissionSetArns) {

    $details = aws sso-admin describe-permission-set `
        --instance-arn $instanceArn `
        --permission-set-arn $psArn `
        --query "PermissionSet" | ConvertFrom-Json

    $managedPolicies = aws sso-admin list-managed-policies-in-permission-set `
        --instance-arn $instanceArn `
        --permission-set-arn $psArn `
        --query "AttachedManagedPolicies[*].Arn" | ConvertFrom-Json

    $permissionSets[$psArn] = [PSCustomObject]@{
        Name            = $details.Name
        PermissionSetArn= $psArn
        Description     = $details.Description
        ManagedPolicies = ($managedPolicies -join "; ")
        SessionDuration = $details.SessionDuration
    }
}

# ---------------------------------------
# Fetch all AWS Accounts
# ---------------------------------------

$accounts = aws organizations list-accounts --query "Accounts" | ConvertFrom-Json

# ---------------------------------------
# Build Final CSV Output
# ---------------------------------------

$results = @()

foreach ($psArn in $permissionSetArns) {
    foreach ($account in $accounts) {

        $assignments = aws sso-admin list-account-assignments `
            --instance-arn $instanceArn `
            --account-id $account.Id `
            --permission-set-arn $psArn `
            --query "AccountAssignments[]" | ConvertFrom-Json

        foreach ($assign in $assignments) {

            if ($assign.PrincipalType -eq "GROUP") {

                $group = $groups | Where-Object { $_.GroupId -eq $assign.PrincipalId }
                $ps = $permissionSets[$psArn]
                $users = $groupUsersMap[$group.GroupId]

                $results += [PSCustomObject]@{
                    GroupName          = $group.DisplayName
                    GroupId            = $group.GroupId
                    UserNames          = $users.UserNames
                    UserDisplayNames   = $users.UserDisplayNames
                    UserEmails         = $users.UserEmails
                    UserStatuses       = $users.UserStatuses
                    PermissionSetName  = $ps.Name
                    PermissionSetArn   = $ps.PermissionSetArn
                    ManagedPolicies    = $ps.ManagedPolicies
                    SessionDuration    = $ps.SessionDuration
                    AccountId          = $account.Id
                    AccountName        = $account.Name
                }
            }
        }
    }
}

# ---------------------------------------
# Export to CSV
# ---------------------------------------

$csvPath = "sso_group_permission_account_with_user_status_and_duration.csv"
$results | Export-Csv -NoTypeInformation -Path $csvPath

Write-Host "CSV generated: $csvPath"
