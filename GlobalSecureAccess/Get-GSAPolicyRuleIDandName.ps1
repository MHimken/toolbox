$Policies = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/networkaccess/filteringPolicies"
foreach ($Policy in $Policies.value) {
    $PolicyId = $Policy.id
    $PolicyName = $Policy.name
    Write-Host "Processing Policy: $PolicyName $PolicyId"
    
    # Get the policy details
    $PolicyDetails = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/networkaccess/filteringPolicies/$PolicyId/?`$expand=policyRules"
    foreach ($Rule in $PolicyDetails.policyRules) {
        Write-Host " - Rule: $($Rule.name) $($Rule.id)"
    }   
}