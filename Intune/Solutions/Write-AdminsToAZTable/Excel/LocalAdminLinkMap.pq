let
    Source = GetAzureAdminTable("LocalAdminCollection"),
    SelectedColumns = Table.SelectColumns(
        Source,
        {
            "PartitionKey",
            "RowKey",
            "UserID",
            "GroupID"
        },
        MissingField.UseNull
    ),
    TypedColumns = Table.TransformColumnTypes(
        SelectedColumns,
        {
            {"PartitionKey", type text},
            {"RowKey", type text},
            {"UserID", type text},
            {"GroupID", type text}
        }
    )
in
    TypedColumns
