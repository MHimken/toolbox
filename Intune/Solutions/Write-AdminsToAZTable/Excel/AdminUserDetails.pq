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
            {"Timestamp", type datetimezone}
        }
    )
in
    TypedColumns
