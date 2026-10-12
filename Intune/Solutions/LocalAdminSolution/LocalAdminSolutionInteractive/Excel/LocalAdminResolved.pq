let
    Main = GetAzureAdminTable("LocalAdminCollection"),
    MainColumnOrder = List.Union({Table.ColumnNames(Main), {"PrincipalID", "PrincipalType", "MembershipType", "AssignedThroughGroupID"}}),
    NormalizedMain = Table.SelectColumns(
        Main,
        MainColumnOrder,
        MissingField.UseNull
    ),
    AddedUserSID = Table.AddColumn(
        NormalizedMain,
        "_UserSID",
        each if [PrincipalType] = "User" then [PrincipalID] else null,
        type text
    ),
    AddedGroupSID = Table.AddColumn(
        AddedUserSID,
        "_GroupSID",
        each if [PrincipalType] = "Group" then [PrincipalID] else null,
        type text
    ),
    JoinedUsers = Table.NestedJoin(
        AddedGroupSID,
        {"_UserSID"},
        AdminUserDetails,
        {"UserID"},
        "_UserDetails",
        JoinKind.LeftOuter
    ),
    ExpandedUsers = Table.ExpandTableColumn(
        JoinedUsers,
        "_UserDetails",
        {"SamAccountName"},
        {"_ResolvedUserName"}
    ),
    JoinedGroups = Table.NestedJoin(
        ExpandedUsers,
        {"_GroupSID"},
        AdminGroupDetails,
        {"GroupID"},
        "_GroupDetails",
        JoinKind.LeftOuter
    ),
    ExpandedGroups = Table.ExpandTableColumn(
        JoinedGroups,
        "_GroupDetails",
        {"GroupName"},
        {"_ResolvedGroupName"}
    ),
    JoinedAssignedThroughGroups = Table.NestedJoin(
        ExpandedGroups,
        {"AssignedThroughGroupID"},
        AdminGroupDetails,
        {"GroupID"},
        "_AssignedThroughGroupDetails",
        JoinKind.LeftOuter
    ),
    ExpandedAssignedThroughGroups = Table.ExpandTableColumn(
        JoinedAssignedThroughGroups,
        "_AssignedThroughGroupDetails",
        {"GroupName"},
        {"_ResolvedAssignedThroughGroupName"}
    ),
    AddedUserName = Table.AddColumn(
        ExpandedAssignedThroughGroups,
        "UserName",
        each
            if [_UserSID] = null then
                null
            else if [_ResolvedUserName] = null or Text.Trim([_ResolvedUserName]) = "" then
                [_UserSID]
            else
                [_ResolvedUserName],
        type text
    ),
    AddedGroupName = Table.AddColumn(
        AddedUserName,
        "GroupName",
        each
            if [_GroupSID] = null then
                null
            else if [_ResolvedGroupName] = null or Text.Trim([_ResolvedGroupName]) = "" then
                [_GroupSID]
            else
                [_ResolvedGroupName],
        type text
    ),
    AddedAssignedThroughGroupName = Table.AddColumn(
        AddedGroupName,
        "AddedThroughGroupName",
        each
            if [AssignedThroughGroupID] = null then
                null
            else if [_ResolvedAssignedThroughGroupName] = null or Text.Trim([_ResolvedAssignedThroughGroupName]) = "" then
                [AssignedThroughGroupID]
            else
                [_ResolvedAssignedThroughGroupName],
        type text
    ),
    RemovedTechnicalColumns = Table.RemoveColumns(
        AddedAssignedThroughGroupName,
        {
            "PrincipalID",
            "PrincipalType",
            "AssignedThroughGroupID",
            "_UserSID",
            "_GroupSID",
            "_ResolvedUserName",
            "_ResolvedGroupName",
            "_ResolvedAssignedThroughGroupName"
        },
        MissingField.Ignore
    ),
    RenamedPresentationColumns = Table.RenameColumns(
        RemovedTechnicalColumns,
        {
            {"Computername", "ComputerName"},
            {"PartitionKey", "SID"}
        },
        MissingField.Ignore
    ),
    PresentationColumnOrder = List.Combine(
        {
            {"ComputerName", "SID"},
            List.Combine(
                List.Transform(
                    List.RemoveItems(MainColumnOrder, {"Computername", "PartitionKey", "PrincipalType"}),
                    each
                        if _ = "PrincipalID" then {"UserName", "GroupName"}
                        else if _ = "AssignedThroughGroupID" then {"AddedThroughGroupName"}
                        else {_}
                )
            )
        }
    ),
    RestoredColumnOrder = Table.SelectColumns(
        RenamedPresentationColumns,
        PresentationColumnOrder,
        MissingField.UseNull
    ),
    TranslatedJoinState = Table.TransformColumns(
        RestoredColumnOrder,
        {
            {
                "EntraOrHybrid",
                each
                    if _ = null then null
                    else if Text.From(_) = "1" then "Entra joined"
                    else if Text.From(_) = "2" then "Hybrid joined"
                    else if Text.From(_) = "3" then "Domain joined"
                    else "Unknown (" & Text.From(_) & ")",
                type text
            }
        }
    ),
    TypedRowKey = Table.TransformColumnTypes(
        TranslatedJoinState,
        {{"RowKey", Int64.Type}}
    ),
    SortedRows = Table.Sort(
        TypedRowKey,
        {{"RowKey", Order.Ascending}}
    )
in
    SortedRows