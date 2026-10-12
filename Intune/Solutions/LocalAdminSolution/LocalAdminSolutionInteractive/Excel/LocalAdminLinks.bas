Attribute VB_Name = "LocalAdminLinks"
Option Explicit

Public Sub RefreshLocalAdminView()
    ThisWorkbook.RefreshAll
    Application.CalculateUntilAsyncQueriesDone
    BuildLocalAdminDetailLinks
End Sub

Public Sub BuildLocalAdminDetailLinks()
    Dim summaryTable As ListObject
    Dim linkMapTable As ListObject
    Dim userTable As ListObject
    Dim groupTable As ListObject

    Set summaryTable = FindTable("LocalAdminResolved")
    Set linkMapTable = FindTable("LocalAdminLinkMap")
    Set userTable = FindTable("AdminUserDetails")
    Set groupTable = FindTable("AdminGroupDetails")

    If summaryTable Is Nothing Or linkMapTable Is Nothing _
        Or userTable Is Nothing Or groupTable Is Nothing Then
        Err.Raise vbObjectError + 1000, "BuildLocalAdminDetailLinks", _
            "Load LocalAdminResolved, LocalAdminLinkMap, AdminUserDetails, and AdminGroupDetails as Excel tables first."
    End If

    Dim linkRows As Object
    Dim userTargets As Object
    Dim groupTargets As Object

    Set linkRows = CreateObject("Scripting.Dictionary")
    Set userTargets = CreateObject("Scripting.Dictionary")
    Set groupTargets = CreateObject("Scripting.Dictionary")

    IndexLinkRows linkMapTable, linkRows
    IndexDetailRows userTable, "UserID", "SamAccountName", userTargets
    IndexDetailRows groupTable, "GroupID", "GroupName", groupTargets

    ApplyDetailLinks summaryTable, linkRows, userTargets, groupTargets
End Sub

Private Function FindTable(ByVal tableName As String) As ListObject
    Dim worksheetItem As Worksheet
    Dim tableItem As ListObject

    For Each worksheetItem In ThisWorkbook.Worksheets
        For Each tableItem In worksheetItem.ListObjects
            If StrComp(tableItem.Name, tableName, vbTextCompare) = 0 Then
                Set FindTable = tableItem
                Exit Function
            End If
        Next tableItem
    Next worksheetItem
End Function

Private Sub IndexLinkRows(ByVal sourceTable As ListObject, ByVal index As Object)
    If sourceTable.DataBodyRange Is Nothing Then Exit Sub

    Dim rowNumber As Long
    Dim recordKey As String
    Dim principalId As String
    Dim principalType As String
    Dim assignedThroughGroupId As String

    For rowNumber = 1 To sourceTable.DataBodyRange.Rows.Count
        recordKey = BuildRecordKey( _
            sourceTable.ListColumns("PartitionKey").DataBodyRange.Cells(rowNumber, 1).Value2, _
            sourceTable.ListColumns("RowKey").DataBodyRange.Cells(rowNumber, 1).Value2)
        principalId = CStr(sourceTable.ListColumns("PrincipalID").DataBodyRange.Cells(rowNumber, 1).Value2)
        principalType = CStr(sourceTable.ListColumns("PrincipalType").DataBodyRange.Cells(rowNumber, 1).Value2)
        assignedThroughGroupId = CStr(sourceTable.ListColumns("AssignedThroughGroupID").DataBodyRange.Cells(rowNumber, 1).Value2)
        index(recordKey) = Array(principalId, principalType, assignedThroughGroupId)
    Next rowNumber
End Sub

Private Sub IndexDetailRows( _
    ByVal sourceTable As ListObject, _
    ByVal idColumnName As String, _
    ByVal displayColumnName As String, _
    ByVal index As Object)

    If sourceTable.DataBodyRange Is Nothing Then Exit Sub

    Dim rowNumber As Long
    Dim principalId As String
    Dim targetCell As Range

    For rowNumber = 1 To sourceTable.DataBodyRange.Rows.Count
        principalId = CStr(sourceTable.ListColumns(idColumnName).DataBodyRange.Cells(rowNumber, 1).Value2)
        If Len(principalId) > 0 Then
            Set targetCell = sourceTable.ListColumns(displayColumnName).DataBodyRange.Cells(rowNumber, 1)
            index(principalId) = InternalAddress(targetCell)
        End If
    Next rowNumber
End Sub

Private Sub ApplyDetailLinks( _
    ByVal summaryTable As ListObject, _
    ByVal linkRows As Object, _
    ByVal userTargets As Object, _
    ByVal groupTargets As Object)

    If summaryTable.DataBodyRange Is Nothing Then Exit Sub

    Dim rowNumber As Long
    Dim recordKey As String
    Dim principalIds As Variant
    Dim targetAddress As String

    For rowNumber = 1 To summaryTable.DataBodyRange.Rows.Count
        recordKey = BuildRecordKey( _
            summaryTable.ListColumns("SID").DataBodyRange.Cells(rowNumber, 1).Value2, _
            summaryTable.ListColumns("RowKey").DataBodyRange.Cells(rowNumber, 1).Value2)

        RemoveCellLink summaryTable.ListColumns("UserName").DataBodyRange.Cells(rowNumber, 1)
        RemoveCellLink summaryTable.ListColumns("GroupName").DataBodyRange.Cells(rowNumber, 1)
        RemoveCellLink summaryTable.ListColumns("AddedThroughGroupName").DataBodyRange.Cells(rowNumber, 1)

        If linkRows.Exists(recordKey) Then
            principalIds = linkRows(recordKey)

            If StrComp(CStr(principalIds(1)), "User", vbTextCompare) = 0 _
                And Len(CStr(principalIds(0))) > 0 _
                And userTargets.Exists(CStr(principalIds(0))) Then
                targetAddress = userTargets(CStr(principalIds(0)))
                AddCellLink summaryTable.ListColumns("UserName").DataBodyRange.Cells(rowNumber, 1), targetAddress
            End If

            If StrComp(CStr(principalIds(1)), "Group", vbTextCompare) = 0 _
                And Len(CStr(principalIds(0))) > 0 _
                And groupTargets.Exists(CStr(principalIds(0))) Then
                targetAddress = groupTargets(CStr(principalIds(0)))
                AddCellLink summaryTable.ListColumns("GroupName").DataBodyRange.Cells(rowNumber, 1), targetAddress
            End If

            If Len(CStr(principalIds(2))) > 0 And groupTargets.Exists(CStr(principalIds(2))) Then
                targetAddress = groupTargets(CStr(principalIds(2)))
                AddCellLink summaryTable.ListColumns("AddedThroughGroupName").DataBodyRange.Cells(rowNumber, 1), targetAddress
            End If
        End If
    Next rowNumber
End Sub

Private Function BuildRecordKey(ByVal partitionKey As Variant, ByVal rowKey As Variant) As String
    BuildRecordKey = CStr(partitionKey) & ChrW(30) & CStr(rowKey)
End Function

Private Function InternalAddress(ByVal targetCell As Range) As String
    InternalAddress = "'" & Replace(targetCell.Worksheet.Name, "'", "''") & "'!" & targetCell.Address
End Function

Private Sub RemoveCellLink(ByVal targetCell As Range)
    If targetCell.Hyperlinks.Count > 0 Then targetCell.Hyperlinks.Delete
End Sub

Private Sub AddCellLink(ByVal targetCell As Range, ByVal targetAddress As String)
    If Len(CStr(targetCell.Value2)) = 0 Then Exit Sub

    targetCell.Worksheet.Hyperlinks.Add _
        Anchor:=targetCell, _
        Address:="", _
        SubAddress:=targetAddress, _
        TextToDisplay:=CStr(targetCell.Value2)
End Sub
