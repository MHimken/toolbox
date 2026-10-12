let
    Source = GetAzureAdminTable("LocalAdminCollection"),
    SelectedColumns = Table.SelectColumns(
        Source,
        {
            "PartitionKey",
            "RowKey",
            "PrincipalID",
            "PrincipalType",
            "AssignedThroughGroupID"
        },
        MissingField.UseNull
    ),
    TypedColumns = Table.TransformColumnTypes(
        SelectedColumns,
        {
            {"PartitionKey", type text},
            {"RowKey", type text},
            {"PrincipalID", type text},
            {"PrincipalType", type text},
            {"AssignedThroughGroupID", type text}
        }
    )
in
    TypedColumns
