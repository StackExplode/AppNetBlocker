#include <windows.h>
#include <fwpmu.h>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <codecvt>
#include <iomanip>
#include <cwctype>
#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "Ws2_32.lib")

const GUID mysublayer = { 0xaa2b6cdd, 0x516f, 0x738b, { 0x1d, 0x5d, 0xe1, 0xf2, 0x34, 0x56, 0x78, 0x93 } }; // ʾ���Ӳ� GUID

// Wildcard matching function supporting * and ?
// * matches any sequence of characters (including empty)
// ? matches exactly one character
bool wildcardMatch(const wchar_t* pattern, const wchar_t* str) {
	const wchar_t* p = pattern;
	const wchar_t* s = str;
	const wchar_t* starBacktrack = nullptr;
	const wchar_t* strBacktrack = nullptr;

	while (*s) {
		if (*p == L'?' || towlower(*p) == towlower(*s)) {
			// Match single character or ?
			++p;
			++s;
		}
		else if (*p == L'*') {
			// Found *, save position for backtracking
			starBacktrack = p++;
			strBacktrack = s;
		}
		else if (starBacktrack) {
			// Mismatch, backtrack to last *
			p = starBacktrack + 1;
			s = ++strBacktrack;
		}
		else {
			// No match
			return false;
		}
	}

	// Skip trailing * in pattern
	while (*p == L'*') {
		++p;
	}

	return *p == L'\0';
}

bool isExePathMatch(const FWP_BYTE_BLOB* blob, const std::wstring& exePath) {
	if (!blob || blob->size % sizeof(wchar_t) != 0) return false;
	std::wstring blobStr((wchar_t*)blob->data, blob->size / sizeof(wchar_t));
	return _wcsicmp(blobStr.c_str(), exePath.c_str()) == 0;
}

bool ByteBlobEqual(const FWP_BYTE_BLOB* a, const FWP_BYTE_BLOB* b) {
	if (!a || !b) return false;
	if (a->size != b->size) return false;
	if (a->size == 0) return true;
	return (memcmp(a->data, b->data, a->size) == 0);
}

// �� wstring תΪ utf8 string������ cout
std::string ws2s_old(const std::wstring& ws) {
	std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
	return conv.to_bytes(ws);
}

std::string ws2s(const std::wstring& input)
{
	// ��ȡ��ǰϵͳ��ANSI����ҳ
	UINT codepage = GetACP();
	// ����Ŀ���ַ��������ֽ���
	int bytes = WideCharToMultiByte(codepage, 0, input.c_str(), -1, nullptr, 0, nullptr, nullptr);
	if (bytes <= 1) return std::string();
	// ����Ŀ���ַ����ռ�
	std::string result(bytes - 1, '\0'); // -1ȥ����β\0
	WideCharToMultiByte(codepage, 0, input.c_str(), -1, &result[0], bytes, nullptr, nullptr);
	return result;
}

// �� FWP_BYTE_BLOB ��Ŀ��ַ�·��תΪ string
std::string AppIdBlobToString(const FWP_BYTE_BLOB* blob) {
	if (!blob || blob->size % sizeof(wchar_t) != 0) return "";
	std::wstring ws(reinterpret_cast<const wchar_t*>(blob->data), blob->size / sizeof(wchar_t));
	return ws2s(ws);
}

// ���WFP�Ӳ��Ƿ���ڣ��������򴴽�������Ϊ�Ӳ�GUID
DWORD EnsureWfpSublayerExists(const GUID& subLayerKey)
{
	HANDLE engineHandle = nullptr;
	DWORD result = FwpmEngineOpen0(
		nullptr,            // ���ؼ����
		RPC_C_AUTHN_WINNT,  // Ĭ��������֤
		nullptr,            // Ĭ��������֤
		nullptr,            // Ĭ�ϱ�־
		&engineHandle
	);
	if (result != ERROR_SUCCESS) {
		std::cerr << "FwpmEngineOpen0 failed: " << result << std::endl;
		return result;
	}

	// ��ѯ�Ӳ��Ƿ��Ѵ���
	FWPM_SUBLAYER0* sublayer = nullptr;
	result = FwpmSubLayerGetByKey0(engineHandle, &subLayerKey, &sublayer);
	if (result == ERROR_SUCCESS) {
		// �Ѵ���
		if (sublayer) FwpmFreeMemory0((void**)&sublayer);
		FwpmEngineClose0(engineHandle);
		return ERROR_SUCCESS;
	}
	else if (result != FWP_E_SUBLAYER_NOT_FOUND) {
		// ��������
		std::cerr << "FwpmSubLayerGetByKey0 failed: " << result << std::endl;
		FwpmEngineClose0(engineHandle);
		return result;
	}

	// �������򴴽�
	FWPM_SUBLAYER0 newSublayer = { 0 };
	newSublayer.subLayerKey = subLayerKey;
	newSublayer.displayData.name = (wchar_t*)L"Jennings AppNetBlock Sublayer";
	newSublayer.displayData.description = (wchar_t*)L"Block IPv4 Internet accessing for specific apps";
	newSublayer.flags = FWPM_FILTER_FLAG_PERSISTENT;
	newSublayer.weight = 0x8000;

	result = FwpmSubLayerAdd0(engineHandle, &newSublayer, nullptr);
	if (result != ERROR_SUCCESS) {
		std::cerr << "FwpmSubLayerAdd0 failed: " << result << std::endl;
	}
	FwpmEngineClose0(engineHandle);
	return result;
}

void PrintAllRulesForExe(const std::wstring& exePath) {
	HANDLE engineHandle = nullptr;
	DWORD result = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engineHandle);
	if (result != ERROR_SUCCESS) {
		std::cout << "FwpmEngineOpen0 failed: " << result << std::endl;
		return;
	}

	// Check if pattern contains wildcards
	bool listAll = (exePath == L"*");
	bool hasWildcard = !listAll && (exePath.find(L'*') != std::wstring::npos || exePath.find(L'?') != std::wstring::npos);


	FWP_BYTE_BLOB* appId = nullptr;
	if (!hasWildcard)
	{
		result = FwpmGetAppIdFromFileName0(exePath.c_str(), &appId);
		if (result != ERROR_SUCCESS) {
			std::cout << "FwpmGetAppIdFromFileName0 failed: " << result << std::endl;
			FwpmEngineClose0(engineHandle);
			return;
		}
	}

	HANDLE enumHandle = nullptr;
	result = FwpmFilterCreateEnumHandle0(engineHandle, nullptr, &enumHandle);
	if (result != ERROR_SUCCESS) {
		std::cout << "FwpmFilterCreateEnumHandle0 failed: " << result << std::endl;
		if (!hasWildcard)
			FwpmFreeMemory0((void**)&appId);
		FwpmEngineClose0(engineHandle);
		return;
	}
	UINT32 numReturned = 0;
	FWPM_FILTER0** filters = nullptr;
	int matchCount = 0;
	while (FwpmFilterEnum0(engineHandle, enumHandle, 64, &filters, &numReturned) == ERROR_SUCCESS && numReturned > 0) {
		for (UINT32 i = 0; i < numReturned; ++i) {
			FWPM_FILTER0* filter = filters[i];
			if (filter->subLayerKey != mysublayer) continue; // ֻ����ͨ���Ӳ�Ĺ���
			for (UINT32 j = 0; j < filter->numFilterConditions; ++j) {
				const FWPM_FILTER_CONDITION0& cond = filter->filterCondition[j];
				if (cond.fieldKey == FWPM_CONDITION_ALE_APP_ID && cond.conditionValue.byteBlob) {
					bool matched = false;
					
					if (listAll) {
						// Match all rules
						matched = true;
					}
					else if (hasWildcard) {
						// Wildcard pattern matching
						if (cond.conditionValue.byteBlob->size % sizeof(wchar_t) == 0) {
							std::wstring blobStr((wchar_t*)cond.conditionValue.byteBlob->data, 
								cond.conditionValue.byteBlob->size / sizeof(wchar_t));
							matched = wildcardMatch(exePath.c_str(), blobStr.c_str());
						}
					}
					else {
						// Exact match
						matched = (cond.conditionValue.byteBlob->size == appId->size &&
							memcmp(cond.conditionValue.byteBlob->data, appId->data, appId->size) == 0);
					}
					
					if (matched) {
						std::cout << "Rule #" << (++matchCount) << ":\n";
						std::cout << "  FilterId: " << filter->filterId << "\n";
						std::cout << "  Name: " << ws2s(filter->displayData.name ? filter->displayData.name : L"(none)") << "\n";
						std::cout << "  Layer: " << ws2s(filter->layerKey == FWPM_LAYER_ALE_AUTH_CONNECT_V4 ? L"AUTH_CONNECT_V4" :
							filter->layerKey == FWPM_LAYER_ALE_AUTH_CONNECT_V6 ? L"AUTH_CONNECT_V6" :
							L"other") << "\n";
						std::cout << "  AppId: " << AppIdBlobToString(cond.conditionValue.byteBlob) << "\n";
						std::cout << " Description: " << (ws2s(filter->displayData.description ? filter->displayData.description : L"(none)")) << "\n";
						std::cout << "--------------------------------------\n";
						break;
					}
				}
			}
		}
		FwpmFreeMemory0((void**)&filters);
	}
	if (matchCount == 0) {
		std::cout << "û���ҵ�����ƥ��·���Ĺ���: " << ws2s(exePath) << std::endl;
	}
	FwpmFilterDestroyEnumHandle0(engineHandle, enumHandle);
	if (!hasWildcard)
		FwpmFreeMemory0((void**)&appId);
	FwpmEngineClose0(engineHandle);
}



int main(int argc, char* argv[]) {
	//std::setlocale(LC_ALL, ".UTF-8");
	if (argc < 3) {
		std::cout << "�÷�: " << argv[0] << " list|add|del C:\\Path\\To\\blockme.exe" << std::endl;
		std::cout << "���ߣ� "<< argv[0] << " delid <FilterId>" << std::endl;
		return 1;
	}
	std::string op = argv[1];
	std::wstring exePath;
	{
		UINT codePage = GetACP();
		int size = MultiByteToWideChar(codePage, 0, argv[2], -1, NULL, 0);
		exePath.resize(size - 1);
		MultiByteToWideChar(codePage, 0, argv[2], -1, &exePath[0], size);
	}

	HANDLE engineHandle = nullptr;
	DWORD result = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engineHandle);
	if (result != ERROR_SUCCESS) {
		std::cout << "FwpmEngineOpen0 failed: " << result << std::endl;
		return 1;
	}

	EnsureWfpSublayerExists(mysublayer);

	if (op == "add") {
		FWPM_FILTER_CONDITION0 cond[2] = {};

		FWP_BYTE_BLOB* appId = nullptr;
		DWORD status = FwpmGetAppIdFromFileName0(exePath.c_str(), &appId);
		if (status != ERROR_SUCCESS) {
			std::cout << "FwpmGetAppIdFromFileName0 failed: " << status << std::endl;
			return 1;
		}

		FWP_BYTE_BLOB appBlob;
		appBlob.size = (UINT32)(exePath.size() * sizeof(wchar_t));
		appBlob.data = (UINT8*)exePath.c_str();
		cond[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
		cond[0].matchType = FWP_MATCH_EQUAL;
		cond[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
		cond[0].conditionValue.byteBlob = appId;

		FWP_V4_ADDR_AND_MASK remoteAddr = {};
		remoteAddr.addr = htonl(0x7F000000); // 127.0.0.0
		remoteAddr.mask = 0xFF000000;        // /8
		cond[1].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
		cond[1].matchType = FWP_MATCH_NOT_EQUAL;
		cond[1].conditionValue.type = FWP_V4_ADDR_MASK;
		cond[1].conditionValue.v4AddrMask = &remoteAddr;

		FWPM_FILTER0 filter = {};
		filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
		filter.displayData.name = (wchar_t*)L"Block exe internet";
		wchar_t buffer[1024];
		swprintf_s(buffer, L"��ֹ %s ���ʻ������������ػ���", exePath.c_str());
		filter.displayData.description = (wchar_t*)buffer;
		filter.action.type = FWP_ACTION_BLOCK;
		filter.filterCondition = cond;
		filter.numFilterConditions = 2;
		filter.subLayerKey = mysublayer;
		filter.weight.type = FWP_EMPTY;
		filter.flags = FWPM_FILTER_FLAG_PERSISTENT; // �־û�
		filter.providerKey = nullptr;

		UINT64 filterId = 0;
		result = FwpmFilterAdd0(engineHandle, &filter, nullptr, &filterId);
		if (result != ERROR_SUCCESS) {
			std::cout << "FwpmFilterAdd0 failed: 0x" << std::setfill('0') << std::setw(8) << std::hex << std::uppercase << result << std::endl;
		}
		else {
			std::cout << "�����ӹ�����ֹ " << exePath.c_str() << " ���ʻ������������ػ���\n";
		}
		FwpmFreeMemory0((void**)&appId);
	}
	else if (op == "del") {

		FWP_BYTE_BLOB* appId = nullptr;
		DWORD status = FwpmGetAppIdFromFileName0(exePath.c_str(), &appId);
		if (status != ERROR_SUCCESS) {
			std::cout << "FwpmGetAppIdFromFileName0 failed: " << status << std::endl;
			return 1;
		}

		HANDLE enumHandle = nullptr;
		result = FwpmFilterCreateEnumHandle0(engineHandle, nullptr, &enumHandle);
		if (result != ERROR_SUCCESS) {
			std::cout << "FwpmFilterCreateEnumHandle0 failed: " << result << std::endl;
			FwpmEngineClose0(engineHandle);
			return 1;
		}
		UINT32 numReturned = 0;
		FWPM_FILTER0** filters = nullptr;
		std::vector<UINT64> idsToDelete;
		while (FwpmFilterEnum0(engineHandle, enumHandle, 64, &filters, &numReturned) == ERROR_SUCCESS && numReturned > 0) {
			for (UINT32 i = 0; i < numReturned; ++i) {
				FWPM_FILTER0* filter = filters[i];
				if (filter->layerKey == FWPM_LAYER_ALE_AUTH_CONNECT_V4 && filter->numFilterConditions >= 1 && filter->subLayerKey == mysublayer) {
					for (UINT32 j = 0; j < filter->numFilterConditions; ++j) {
						if (filter->filterCondition[j].fieldKey == FWPM_CONDITION_ALE_APP_ID) {
							const FWP_BYTE_BLOB* blob = filter->filterCondition[j].conditionValue.byteBlob;
							if (ByteBlobEqual(blob, appId)) {
								idsToDelete.push_back(filter->filterId);
								break;
							}
						}
					}
				}
			}
			FwpmFreeMemory0((void**)&filters);
		}
		for (auto id : idsToDelete) {
			FwpmFilterDeleteById0(engineHandle, id);
		}
		std::cout << "��ɾ�� " << idsToDelete.size() << " ��ƥ�����\n";
		FwpmFreeMemory0((void**)&appId);
		FwpmFilterDestroyEnumHandle0(engineHandle, enumHandle);
	}
	else if (op == "list") {
		PrintAllRulesForExe(exePath);
	}
	else if (op == "delid")
	{

		UINT64 filterId = _strtoui64(argv[2], nullptr, 10);
		result = FwpmFilterDeleteById0(engineHandle, filterId);
		if (result != ERROR_SUCCESS) {
			std::cout << "FwpmFilterDeleteById0 failed: " << result << std::endl;
		}
		else {
			std::cout << "��ɾ�� FilterId: " << filterId << std::endl;
		}
	}
	else {
		std::cout << "δ֪������" << op << std::endl;
	}
	
	FwpmEngineClose0(engineHandle);
	return 0;
}