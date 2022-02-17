SetCompressor /SOLID lzma
Unicode True

!define MULTIUSER_EXECUTIONLEVEL Highest
!define MULTIUSER_MUI
!define MULTIUSER_INSTALLMODE_COMMANDLINE
!include "MultiUser.nsh"
!include "MUI2.nsh"

!include "x64.nsh"

; Read the command-line parameters
!insertmacro GetParameters
!insertmacro GetOptions

;--------------------------------
;Configuration

;General

; Package name as shown in the installer GUI
Name "mycms ${PACKAGE_NAME}-${PACKAGE_VERSION} (${PACKAGE_BUILD_ID})"

InstallDir "$PROGRAMFILES64\mycms"

; Installer filename
OutFile "${OUTPUT}"

ShowInstDetails show
ShowUninstDetails show

;Remember install folder
InstallDirRegKey HKLM "SOFTWARE\${PACKAGE_NAME}" ""

;======================================================
; Version Information

VIProductVersion "1.0.0.0"
VIAddVersionKey "ProductName" "${PACKAGE_NAME}-Installer"
VIAddVersionKey "Comments" ""
VIAddVersionKey "CompanyName" "mycms"
VIAddVersionKey "LegalTrademarks" "mycms"
VIAddVersionKey "LegalCopyright" "mycms"
VIAddVersionKey "FileDescription" "${PACKAGE_NAME}-Installer"
VIAddVersionKey "FileVersion" "1.0.0"

;--------------------------------
;Modern UI Configuration

; Compile-time constants which we'll need during install
!define MUI_WELCOMEPAGE_TEXT "This wizard will guide you through the installation of mycms.$\r$\n$\r$\n"

!define MUI_COMPONENTSPAGE_TEXT_TOP "Select the components to install/upgrade.  Stop any mycms processes or the mycms service if it is running.  All DLLs are installed locally."

!define MUI_COMPONENTSPAGE_SMALLDESC

!define MUI_ABORTWARNING
!define MUI_ICON "icon.ico"
!define MUI_UNICON "icon.ico"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "install-whirl.bmp"
!define MUI_UNFINISHPAGE_NOAUTOCLOSE

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${DESTDIR}\share\doc\mycms\COPYING"
!insertmacro MULTIUSER_PAGE_INSTALLMODE
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

;--------------------------------
;Languages

!insertmacro MUI_LANGUAGE "English"

;--------------------------------
;Language Strings

!if ${WITH_CRYPTO} == "openssl"
LangString DESC_SecOpenSSLLibraries ${LANG_ENGLISH} "Install OpenSSL libraries"
!endif
LangString DESC_SecMycmsLibraries ${LANG_ENGLISH} "Install mycms libraries"
LangString DESC_SecMycmsTools ${LANG_ENGLISH} "Install mycms tools"
LangString DESC_SecMycmsSDK ${LANG_ENGLISH} "Install mycms SDK"

;--------------------------------
;Reserve Files

;Things that need to be extracted on first (keep these lines before any File command!)
;Only useful for BZIP2 compression

ReserveFile "install-whirl.bmp"

;--------------------------------
;Macros

!macro SelectByParameter SECT PARAMETER DEFAULT
	${GetOptions} $R0 "/${PARAMETER}=" $0
	${If} ${DEFAULT} == 0
		${If} $0 == 1
			!insertmacro SelectSection ${SECT}
		${EndIf}
	${Else}
		${If} $0 != 0
			!insertmacro SelectSection ${SECT}
		${EndIf}
	${EndIf}
!macroend

;--------------------
;Pre-install section

!if ${WITH_CRYPTO} == "openssl"
Section "openssl libraries" SecOpenSSLLibraries

	SetOverwrite on

	SetOutPath "$INSTDIR\bin"
	File "${DESTDIR}\bin\libcrypto-*-x64.dll"

SectionEnd
!endif

Section "mycms libraries" SecMycmsLibraries

	SectionIn RO ; section cannot be unchecked by user
	SetOverwrite on

	SetOutPath "$INSTDIR\bin"
	File "${DESTDIR}\bin\libmycms-1.dll"
	File "${DESTDIR}\bin\libmycms-util-1.dll"

	SetOutPath "$INSTDIR\doc"
	File "${DESTDIR}\share\doc\mycms\README.md"

SectionEnd

Section /o "mycms Tools" SecMycmsTools

	SetOverwrite on

	SetOutPath "$INSTDIR\bin"
	File "${DESTDIR}\bin\mycms-tool.exe"

SectionEnd

Section /o "mycms SDK" SecMycmsSDK

	SetOverwrite on

	SetOutPath "$INSTDIR\include\mycms"
	File "${DESTDIR}\include\mycms\*"

	SetOutPath "$INSTDIR\lib"
	File "${DESTDIR}\lib\libmycms-1.dll.def"
	File "${DESTDIR}\lib\libmycms-util-1.dll.def"

SectionEnd

;--------------------------------
;Installer Sections

Function .onInit
	${GetParameters} $R0
	ClearErrors

	SetRegView 64

!if ${WITH_CRYPTO} == "openssl"
	!insertmacro SelectByParameter ${SecOpenSSLLibraries} SELECT_OPENVPN_LIBRARIES 1
!endif
	!insertmacro SelectByParameter ${SecMycmsLibraries} SELECT_MYCMS_LIBRARIES 1
	!insertmacro SelectByParameter ${SecMycmsTools} SELECT_MYCMS_TOOLS 1
	!insertmacro SelectByParameter ${SecMycmsSDK} SELECT_MYCMS_SDK 0

	!insertmacro MULTIUSER_INIT
	SetShellVarContext all

FunctionEnd

;--------------------------------
;Dependencies

Function .onSelChange
	${If} ${SectionIsSelected} ${SecMycmsTools}
		!insertmacro SelectSection ${SecMycmsLibraries}
	${EndIf}
	${If} ${SectionIsSelected} ${SecMycmsSDK}
		!insertmacro SelectSection ${SecMycmsLibraries}
	${EndIf}
FunctionEnd

;--------------------
;Post-install section

Section -post

	SetOverwrite on

	SetOutPath "$INSTDIR"
	File "icon.ico"

	SetOutPath "$INSTDIR\doc"
	File "${DESTDIR}\share\doc\mycms\COPYING"

	; Store install folder in registry
	WriteRegStr HKLM "SOFTWARE\${PACKAGE_NAME}" "" "$INSTDIR"

	; Create uninstaller
	WriteUninstaller "$INSTDIR\Uninstall.exe"
	WriteRegStr HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${PACKAGE_NAME}" "DisplayName" "${PACKAGE_NAME}-${PACKAGE_VERSION} (${PACKAGE_BUILD_ID})"
	WriteRegExpandStr HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${PACKAGE_NAME}" "UninstallString" "$INSTDIR\Uninstall.exe"
	WriteRegStr HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${PACKAGE_NAME}" "DisplayIcon" "$INSTDIR\icon.ico"
	WriteRegStr HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${PACKAGE_NAME}" "DisplayVersion" "${PACKAGE_VERSION} (${PACKAGE_BUILD_ID})}"
	WriteRegStr HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${PACKAGE_NAME}" "HelpLink" "https://github.com/alonbl/mycms"
	WriteRegStr HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${PACKAGE_NAME}" "InstallLocation" "$INSTDIR\"
	WriteRegDWORD HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${PACKAGE_NAME}" "Language" 1033
	WriteRegStr HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${PACKAGE_NAME}" "Publisher" "mycms"
	WriteRegStr HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${PACKAGE_NAME}" "UninstallString" "$INSTDIR\Uninstall.exe"
	WriteRegStr HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${PACKAGE_NAME}" "URLInfoAbout" "https://github.com/alonbl/mycms"

	${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
	IntFmt $0 "0x%08X" $0
	WriteRegDWORD HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${PACKAGE_NAME}" "EstimatedSize" "$0"

SectionEnd

;--------------------------------
;Descriptions

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
!if ${WITH_CRYPTO} == "openssl"
	!insertmacro MUI_DESCRIPTION_TEXT ${SecOpenSSLLibraries} $(DESC_SecOpenSSLLibraries)
!endif
	!insertmacro MUI_DESCRIPTION_TEXT ${SecMycmsLibraries} $(DESC_SecMycmsLibraries)
	!insertmacro MUI_DESCRIPTION_TEXT ${SecMycmsTools} $(DESC_SecMycmsTools)
	!insertmacro MUI_DESCRIPTION_TEXT ${SecMycmsSDK} $(DESC_SecMycmsSDK)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

;--------------------------------
;Uninstaller Section

Function un.onInit

	ClearErrors
	!insertmacro MULTIUSER_UNINIT
	SetShellVarContext all
	SetRegView 64

FunctionEnd

Section "Uninstall"

	Delete "$INSTDIR\Uninstall.exe"
	Delete "$INSTDIR\bin\libcrypto-*-x64.dll"
	Delete "$INSTDIR\bin\libmycms-1.dll"
	Delete "$INSTDIR\bin\libmycms-util-1.dll"
	Delete "$INSTDIR\bin\mycms-tool.exe"
	Delete "$INSTDIR\doc\COPYING"
	Delete "$INSTDIR\doc\README.md"
	Delete "$INSTDIR\icon.ico"

	RMDir "$INSTDIR\bin"
	RMDir "$INSTDIR\doc"
	RMDir /r "$INSTDIR\include"
	RMDir /r "$INSTDIR\lib"

	RMDir "$INSTDIR"

	DeleteRegKey HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${PACKAGE_NAME}"

SectionEnd
