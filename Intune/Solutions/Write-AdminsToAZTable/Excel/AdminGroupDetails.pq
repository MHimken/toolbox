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
            {"Timestamp", type datetimezone}
        }
    )
in
    TypedColumns
