(tableName as text) as table =>
let
    AccountUrl = Text.TrimEnd(Text.Trim(StorageAccountUrl), "/"),
    SasToken = Text.TrimStart(Text.Trim(StorageSasToken), "?"),
    ValidatedAccountUrl =
        if Text.StartsWith(AccountUrl, "https://") then
            AccountUrl
        else
            error Error.Record("Configuration", "StorageAccountUrl must use HTTPS.", AccountUrl),
    ValidatedToken =
        if Text.Length(SasToken) > 0 then
            SasToken
        else
            error Error.Record("Configuration", "StorageSasToken is empty.", null),
    SasQuery = Uri.Parts("https://localhost/?" & ValidatedToken)[Query],
    GetHeader = (headers as record, headerName as text) as nullable text =>
        let
            MatchingFields = List.Select(
                Record.FieldNames(headers),
                each Text.Lower(_) = Text.Lower(headerName)
            )
        in
            if List.IsEmpty(MatchingFields) then
                null
            else
                Text.From(Record.Field(headers, MatchingFields{0})),
    GetPage = (continuation as nullable record) as record =>
        let
            QueryOptions =
                if continuation = null then
                    SasQuery
                else
                    Record.Combine({SasQuery, continuation}),
            Response = Web.Contents(
                ValidatedAccountUrl,
                [
                    RelativePath = tableName & "()",
                    Query = QueryOptions,
                    Headers = [
                        Accept = "application/json;odata=nometadata",
                        DataServiceVersion = "3.0;NetFx",
                        MaxDataServiceVersion = "3.0;NetFx",
                        #"x-ms-version" = "2023-11-03"
                    ]
                ]
            ),
            Payload = Json.Document(Response),
            ResponseHeaders = Record.FieldOrDefault(Value.Metadata(Response), "Headers", []),
            NextPartitionKey = GetHeader(ResponseHeaders, "x-ms-continuation-NextPartitionKey"),
            NextRowKey = GetHeader(ResponseHeaders, "x-ms-continuation-NextRowKey"),
            Next =
                if NextPartitionKey = null then
                    null
                else
                    [
                        NextPartitionKey = NextPartitionKey,
                        NextRowKey = if NextRowKey = null then "" else NextRowKey
                    ]
        in
            [
                Rows = Record.FieldOrDefault(Payload, "value", {}),
                Next = Next
            ],
    Pages = List.Generate(
        () => GetPage(null),
        each _ <> null,
        each if [Next] = null then null else GetPage([Next]),
        each [Rows]
    ),
    Rows = List.Combine(Pages),
    Source =
        if List.IsEmpty(Rows) then
            #table({}, {})
        else
            Table.FromRecords(
                Rows,
                List.Union(List.Transform(Rows, each Record.FieldNames(_))),
                MissingField.UseNull
            )
in
    Source
