#include <QCoreApplication>
#include <QDebug>
#include <windows.h>
#include <ntsecapi.h>

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    if (argc > 1) {
        qInfo() << argv[0];
        //qInfo() << argv[1];
        qInfo() << QCoreApplication::arguments().at(1);
    } else {
        qInfo() << "Please pass SCM:GUID";
        return -1;
    }

    LSA_OBJECT_ATTRIBUTES  obj_attrs;
    LSA_HANDLE h_policy;

    ZeroMemory(&obj_attrs, sizeof(obj_attrs));
    if (LsaOpenPolicy(NULL, &obj_attrs, POLICY_GET_PRIVATE_INFORMATION, &h_policy) != ERROR_SUCCESS) {
    //if (LsaOpenPolicy(NULL, &obj_attrs, POLICY_ALL_ACCESS, &h_policy) != ERROR_SUCCESS) {
        qDebug() << "Unable to call LsaOpenPolicy";
        return -1;
    }

    PLSA_UNICODE_STRING privateData = NULL;
    //WCHAR wstrKeyName[]=L"DefaultPassword";
    //WCHAR wstrKeyName[]=L"SCM:{********-****-****-****-************}";

//    WCHAR wstrKeyName[43] = {};
//    wstrKeyName[42] = L'\0';
//    qDebug() <<":" << wcslen(wstrKeyName);
//    QCoreApplication::arguments().at(1).toWCharArray(wstrKeyName);
//    qDebug() <<":" << wcslen(wstrKeyName);
    auto scm_key = QCoreApplication::arguments().at(1).toStdWString();
    auto wstrKeyName = const_cast<wchar_t *>(scm_key.c_str());

    LSA_UNICODE_STRING keyName;
    keyName.Buffer = wstrKeyName;
    keyName.Length = wcslen(wstrKeyName) * sizeof(WCHAR);
    keyName.MaximumLength = (wcslen(wstrKeyName) + 1) * sizeof(WCHAR);
    NTSTATUS result = LsaRetrievePrivateData(h_policy, &keyName, &privateData);
    if (result != ERROR_SUCCESS)
    {
        qDebug() << "LsaRetrievePrivateData failed : " << LsaNtStatusToWinError(result);
        return -1;
    } else {
        printf("Success...\nPassword:%S\nLength:%d\n", privateData->Buffer, (privateData->Length-1)/sizeof(WCHAR));
    }

    if(h_policy) {
        LsaClose(h_policy);
    }

    qDebug() << "Exiting...";
    return 0;
}
