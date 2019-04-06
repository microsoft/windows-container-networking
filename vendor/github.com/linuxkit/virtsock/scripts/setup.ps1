$service = New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestCommunicationServices" -Name 3049197C-FACB-11E6-BD58-64006A7986D3

$service.SetValue("ElementName", "Hyper-V Socket Play Service")
