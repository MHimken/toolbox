let
    Source = GetAzureAdminTable("AdminUserNames"),
    RenamedKeys = Table.RenameColumns(
        Source,
        {
            {"PartitionKey", "UserID"},
            {"RowKey", "SamAccountName"}
        },
        MissingField.Ignore
    ),
    SelectedColumns = Table.SelectColumns(
        RenamedKeys,
        {
            "UserID",
            "SamAccountName",
            "UserPrincipalName",
            "LocalOrEntraOrAD",
            "ObservedAt",
            "ResolutionState",
            "Timestamp"
        },
        MissingField.UseNull
    ),
    TypedColumns = Table.TransformColumnTypes(
        SelectedColumns,
        {
            {"UserID", type text},
            {"SamAccountName", type text},
            {"UserPrincipalName", type text},
            {"LocalOrEntraOrAD", type text},
            {"ObservedAt", type datetimezone},
            {"ResolutionState", type text},
            {"Timestamp", type datetimezone}
        }
    ),
    AddedResolutionRank = Table.AddColumn(
        TypedColumns,
        "_ResolutionRank",
        each if [ResolutionState] = "Resolved" then 1 else 0,
        Int64.Type
    ),
    AddedObservedSort = Table.AddColumn(
        AddedResolutionRank,
        "_ObservedSort",
        each if [ObservedAt] <> null then [ObservedAt] else [Timestamp],
        type datetimezone
    ),
    CanonicalByUserID = Table.Group(
        AddedObservedSort,
        {"UserID"},
        {
            {
                "Canonical",
                each Table.FirstN(
                    Table.Sort(
                        _,
                        {
                            {"_ResolutionRank", Order.Descending},
                            {"_ObservedSort", Order.Descending},
                            {"SamAccountName", Order.Descending}
                        }
                    ),
                    1
                ),
                type table
            }
        }
    ),
    ExpandedCanonical = Table.ExpandTableColumn(
        CanonicalByUserID,
        "Canonical",
        {
            "SamAccountName",
            "UserPrincipalName",
            "LocalOrEntraOrAD",
            "ObservedAt",
            "ResolutionState",
            "Timestamp"
        }
    )
in
    ExpandedCanonical
