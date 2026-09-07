let
    Source = GetAzureAdminTable("AdminGroups"),
    RenamedKeys = Table.RenameColumns(
        Source,
        {
            {"PartitionKey", "GroupID"},
            {"RowKey", "GroupName"}
        },
        MissingField.Ignore
    ),
    SelectedColumns = Table.SelectColumns(
        RenamedKeys,
        {
            "GroupID",
            "GroupName",
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
            {"GroupID", type text},
            {"GroupName", type text},
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
    CanonicalByGroupID = Table.Group(
        AddedObservedSort,
        {"GroupID"},
        {
            {
                "Canonical",
                each Table.FirstN(
                    Table.Sort(
                        _,
                        {
                            {"_ResolutionRank", Order.Descending},
                            {"_ObservedSort", Order.Descending},
                            {"GroupName", Order.Descending}
                        }
                    ),
                    1
                ),
                type table
            }
        }
    ),
    ExpandedCanonical = Table.ExpandTableColumn(
        CanonicalByGroupID,
        "Canonical",
        {
            "GroupName",
            "LocalOrEntraOrAD",
            "ObservedAt",
            "ResolutionState",
            "Timestamp"
        }
    )
in
    ExpandedCanonical
