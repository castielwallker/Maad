Dim escolha

Do
    escolha = InputBox("Selecionar o Desejado:" & vbCrLf & _
    "(01) - Limpar Temp Files" & vbCrLf & _
    "(02) - Limpar Registro" & vbCrLf & _
    "(03) - Limpar Journal" & vbCrLf & _
    "(04) - Limpar Crash & Event Log" & vbCrLf & _
    "(05) - Desativar Serviço Do Windows" & vbCrLf & _
    "(06) - Trocar Data de Instalação Do Windows" & vbCrLf & _
    "(07) - Desinstalar Multi Theft Auto A Força" & vbCrLf & _
    "(08) - Trocar Dados Do Sistema" & vbCrLf & _
    "(09) - Desativar/Ativar Prefetch" & vbCrLf & _
    "(10) - Sair", "Menu de Limpeza")

    Select Case escolha
        Case "01"
            MsgBox "Limpando arquivos temporários..."
            Set objShell = CreateObject("WScript.Shell")
            objShell.Run "cmd /c del /q/f/s %temp%\*", 0, True

        Case "02"
            MsgBox "Limpando registros..."
            Set objShell = CreateObject("WScript.Shell")
            objShell.Run "cmd /c reg delete HKCU\Software\TempKey /f", 0, True

        Case "03"
            MsgBox "Limpando Journal..."
            Set objShell = CreateObject("WScript.Shell")
            objShell.Run "cmd /c fsutil usn deletejournal /d c:", 0, True

        Case "04"
            MsgBox "Limpando Crash & Event Log..."
            Set objShell = CreateObject("WScript.Shell")
            objShell.Run "cmd /c wevtutil cl Application", 0, True

        Case "05"
            MsgBox "Desativando serviço do Windows..."
            Set objShell = CreateObject("WScript.Shell")
            objShell.Run "cmd /c sc stop wuauserv && sc config wuauserv start=disabled", 0, True

        Case "06"
            MsgBox "Trocando data de instalação do Windows..."
			Set objShell = CreateObject("WScript.Shell")
			Set objShell = GetObject("winmgmts:\\.\root\default:StdRegProv")
			strKeyPath = "SOFTWARE\Microsoft\Windows NT\CurrentVersion"
			strValueName = "InstallDate"
			newTimestamp = 1704067200		
			objShell.SetDWORDValue &H80000002, strKeyPath, strValueName, newTimestamp
        Case "07"
            MsgBox "Desinstalando Multi Theft Auto à força..."
            Set objShell = CreateObject("WScript.Shell")
            objShell.Run "cmd /c taskkill /f /im MultiTheftAuto.exe && rd /s /q C:\Program Files\MTA", 0, True

        Case "08"
            MsgBox "Trocando dados do sistema..."
            Set objShell = CreateObject("WScript.Shell")
            objShell.Run "cmd /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation /v Model /t REG_SZ /d 'Novo Modelo' /f", 0, True

        Case "09"
            MsgBox "Desativando/Ativando Prefetch..."
            Set objShell = CreateObject("WScript.Shell")
            objShell.Run "cmd /c reg add HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters /v EnablePrefetcher /t REG_DWORD /d 0 /f", 0, True

        Case "10"
            MsgBox "Saindo..."
            Exit Do

        Case Else
            MsgBox "Opção inválida. Tente novamente."
    End Select
Loop
