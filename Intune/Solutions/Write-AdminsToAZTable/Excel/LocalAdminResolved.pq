let
    Main = GetAzureAdminTable("LocalAdminCollection"),
    MainColumnOrder = List.Union({Table.ColumnNames(Main), {"UserID", "GroupID"}}),
    NormalizedMain = Table.SelectColumns(
        Main,
        MainColumnOrder,
        MissingField.UseNull
    ),
    LookupKeys = Table.RenameColumns(
        NormalizedMain,
        {
            {"UserID", "_UserSID"},
            {"GroupID", "_GroupSID"}
        },
        MissingField.Ignore
    ),
    JoinedUsers = Table.NestedJoin(
        LookupKeys,
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
    AddedUserName = Table.AddColumn(
        ExpandedGroups,
        "UserID",
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
        "GroupID",
        each
            if [_GroupSID] = null then
                null
            else if [_ResolvedGroupName] = null or Text.Trim([_ResolvedGroupName]) = "" then
                [_GroupSID]
            else
                [_ResolvedGroupName],
        type text
    ),
    RemovedTechnicalColumns = Table.RemoveColumns(
        AddedGroupName,
        {
            "_UserSID",
            "_GroupSID",
            "_ResolvedUserName",
            "_ResolvedGroupName"
        },
        MissingField.Ignore
    ),
    RenamedPresentationColumns = Table.RenameColumns(
        RemovedTechnicalColumns,
        {
            {"Computername", "ComputerName"},
            {"PartitionKey", "SID"},
            {"UserID", "UserName"},
            {"GroupID", "GroupName"}
        },
        MissingField.Ignore
    ),
    PresentationColumnOrder = List.Combine(
        {
            {"ComputerName", "SID"},
            List.Transform(
                List.RemoveItems(MainColumnOrder, {"Computername", "PartitionKey"}),
                each if _ = "UserID" then "UserName" else if _ = "GroupID" then "GroupName" else _
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