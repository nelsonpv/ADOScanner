Set-StrictMode -Version Latest 
class Repo: ADOSVTBase {    
    hidden $RepoId = "";

    Repo([string] $subscriptionId, [SVTResource] $svtResource): Base($subscriptionId, $svtResource) {
        $this.RepoId = $svtResource.ResourceId.split('/')[-1]
    }
    
    hidden [ControlResult] CheckInactiveRepo([ControlResult] $controlResult) {
        $currentDate = Get-Date
        try {
            $projectId = ($this.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
            # check if repo has commits in past ActivityThresholdInDays days
            $thresholdDate = $currentDate.AddDays(-$this.ControlSettings.Repo.ActivityThresholdInDays);
            $url = "https://dev.azure.com/$($this.SubscriptionContext.SubscriptionName)/$projectId/_apis/git/repositories/$($this.RepoId)/commits?searchCriteria.fromDate=$($thresholdDate)&&api-version=6.0"
            $res = [WebRequestHelper]::InvokeGetWebRequest($url);
            # When there are no commits, CheckMember in the below condition returns false when checknull flag [third param in CheckMember] is not specified (default value is $true). Assiging it $false.
            if (([Helpers]::CheckMember($res[0], "count", $false)) -and ($res[0].count -eq 0)) {
                $controlResult.AddMessage([VerificationResult]::Failed, "Repository is inactive. It has no commits in last $($this.ControlSettings.Repo.ActivityThresholdInDays) days.");
            }
            # When there are commits - the below condition will be true.
            elseif ((-not ([Helpers]::CheckMember($res[0], "count"))) -and ($res.Count -gt 0)) {
                $controlResult.AddMessage([VerificationResult]::Passed, "Repository is active. It has commits in last $($this.ControlSettings.Repo.ActivityThresholdInDays) days.");
            }
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the list of inactive repositories in the project.");
        }
        return $controlResult
    }

    hidden [ControlResult] CheckRBACAccess([ControlResult] $controlResult) {
        $projectId = ($this.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
        $url = "https://dev.azure.com/$($this.SubscriptionContext.SubscriptionName)/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1"
        $body = "{
            'contributionIds': [
                'ms.vss-admin-web.security-view-members-data-provider'
            ],
            'dataProviderContext': {
                'properties': {
                    'permissionSetId': '2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87',
                    'permissionSetToken': '',
                    'sourcePage': {
                        'url': '',
                        'routeId': 'ms.vss-admin-web.project-admin-hub-route',
                        'routeValues': {
                            'project': '',
                            'adminPivot': 'repositories',
                            'controller': 'ContributedPage',
                            'action': 'Execute',
                            'serviceHost': ''
                        }
                    }
                }
            }
        }" | ConvertFrom-Json
        $body.dataProviderContext.properties.permissionSetToken = "repoV2/$($projectId)/$($this.RepoId)"
        $body.dataProviderContext.properties.sourcePage.url = "https://dev.azure.com/$($this.SubscriptionContext.SubscriptionName)/$projectId/_settings/repositories?repo=$($this.RepoId)&_a=permissionsMid";
        $body.dataProviderContext.properties.sourcePage.routeValues.project = "$projectId";
        $response = ""
        try {
            $response = [WebRequestHelper]::InvokePostWebRequest($url, $body);
            if ([Helpers]::CheckMember($response, "dataProviders") -and $response.dataProviders.'ms.vss-admin-web.security-view-members-data-provider' -and [Helpers]::CheckMember($response.dataProviders.'ms.vss-admin-web.security-view-members-data-provider', "identities")) {
                $identities = $response.dataProviders.'ms.vss-admin-web.security-view-members-data-provider'.identities
                $names = @()
                foreach ($identity in $identities) {
                    $names += $identity.displayName
                }
                $controlResult.AddMessage([VerificationResult]::Verify, "Validate that the following identities have been provided with minimum RBAC access to [$($this.ResourceContext.ResourceName)] repository.", $names);
                $controlResult.SetStateData("Repository access list: ", $names);
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Manual, "Unable to fetch repository details. Please verify from portal all teams/groups are granted minimum required permissions on repo.");
            }
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Manual, "Unable to fetch repository details. Please verify from portal all teams/groups are granted minimum required permissions on repo.");
        }
        return $controlResult
    }

    hidden [ControlResult] CheckInheritedPermissions([ControlResult] $controlResult) {
        $projectId = ($this.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
        $url = "https://dev.azure.com/$($this.SubscriptionContext.SubscriptionName)/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1"
        $body = "{
            'contributionIds': [
                'ms.vss-admin-web.security-view-data-provider'
            ],
            'dataProviderContext': {
                'properties': {
                    'permissionSetId': '2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87',
                    'permissionSetToken': '',
                    'sourcePage': {
                        'url': '',
                        'routeId': 'ms.vss-admin-web.project-admin-hub-route',
                        'routeValues': {
                            'project': '',
                            'adminPivot': 'repositories',
                            'controller': 'ContributedPage',
                            'action': 'Execute',
                            'serviceHost': ''
                        }
                    }
                }
            }
        }" | ConvertFrom-Json
        $body.dataProviderContext.properties.permissionSetToken = "repoV2/$($projectId)/$($this.RepoId)"
        $body.dataProviderContext.properties.sourcePage.url = "https://dev.azure.com/$($this.SubscriptionContext.SubscriptionName)/$projectId/_settings/repositories?repo=/$($this.RepoId)&_a=permissionsMid";
        $body.dataProviderContext.properties.sourcePage.routeValues.project = "$projectId";
        $response = ""
        try {
            $response = [WebRequestHelper]::InvokePostWebRequest($url, $body);
            if ([Helpers]::CheckMember($response, "dataProviders") -and $response.dataProviders.'ms.vss-admin-web.security-view-data-provider' -and [Helpers]::CheckMember($response.dataProviders.'ms.vss-admin-web.security-view-data-provider', "permissionsContextJson")) {
                $permissionsContextJson = $response.dataProviders.'ms.vss-admin-web.security-view-data-provider'.permissionsContextJson
                $permissionsContextJson = $permissionsContextJson | ConvertFrom-Json
                if ($permissionsContextJson.inheritPermissions) {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Inherited permissions are enabled on this repository.");
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed, "Inherited permissions are disabled on this repository.");
                }
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Error, "Unable to fetch repository details. Please verify from portal that permission inheritance is turned OFF.");
            }
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error, "Unable to fetch repository details. Please verify from portal that permission inheritance is turned OFF.");
        }
        return $controlResult
    }

}