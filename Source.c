#include "ntddk.h"
#include <fwpmk.h>
#include <fwpsk.h>
#define INITGUIID
#include <guiddef.h>
#include <initguid.h>
#include<fwpvi.h>
//#include <fwpmu.h>  

DEFINE_GUID(WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID, 0XD969FC67, 0X6FB2, 0X4504, 0X91, 0xce, 0xa9, 0x7c, 0x3c, 0x32, 0xad, 0x36);
DEFINE_GUID(WFP_SAMPLE_SUB_LAYER_GUID, 0xed6a516a, 0x36d1, 0x4881, 0xbc, 0xf0, 0xac,0xeb, 0x4c, 0x4, 0xc2, 0x1c);
DEFINE_GUID(
	FWPM_CONDITION_IP_LOCAL_PORT,
	0x0c1ba1af,
	0x5765,
	0x453f,
	0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b
);
// 3b89653c-c170-49e4-b1cd-e0eeeee19a3e
DEFINE_GUID(
	FWPM_LAYER_STREAM_V4,
	0x3b89653c,
	0xc170,
	0x49e4,
	0xb1, 0xcd, 0xe0, 0xee, 0xee, 0xe1, 0x9a, 0x3e
);

DEFINE_GUID(
	FWPM_LAYER_ALE_AUTH_CONNECT_V4,
	0xc38d57d1,
	0x05a7,
	0x4c33,
	0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82
);

DEFINE_GUID(
	FWPM_CONDITION_IP_REMOTE_ADDRESS,
	0xb235ae9a,
	0x1d64,
	0x49b8,
	0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45
);

PDEVICE_OBJECT DeviceObject = NULL;
HANDLE EngineHandle;
UINT32 RegCalloutId = 0 , AddCalloutId=0;
UINT64 filterId = 0;

void UnInitWfp() {

}

NTSTATUS NotifyCallback(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID *filterkey , const FWPS_FILTER *filter) {
	return STATUS_SUCCESS;
}
void FlowDeleteCallback(UINT16 layerid, UINT32 calloutid, UINT64 flowcontext) {
	
}
void FilterCallback(const FWPS_INCOMING_VALUES0* Values, const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, PVOID layerData, const void* classifyContext, _In_ const FWPS_FILTER* filter, _In_ UINT64 flowContext, FWPS_CLASSIFY_OUT0* classifyOut) {
	/*
	FWPS_STREAM_CALLOUT_IO_PACKET* packet;
	KdPrint(("DATA IS HERE\r\n"));
	packet = (FWPS_STREAM_CALLOUT_IO_PACKET*)layerData;
	RtlZeroMemory(classifyOut, sizeof(FWPS_CLASSIFY_OUT));
	packet->streamAction = FWPS_STREAM_ACTION_NONE;
	classifyOut->actionType = FWP_ACTION_PERMIT;
	*/

	ULONG LocalIp, RemoteIp;
	ULONG fromTargetip1 = 0x42dc9000; //face ip from 
	ULONG ToTargetip1 = 0x42dc9fff; //face ip
	ULONG fromTargetip2 = 0x453fb000; //face ip from 
	ULONG ToTargetip2 = 0x453fbfff; //face ip
	ULONG fromTargetip3 = 0xcc0f1400; //face ip from 
	ULONG ToTargetip3 = 0xcc0f17ff; //face ip

	ULONG fromTargetip4 = 0x1f0d0000; //face ip from 
	ULONG ToTargetip4 = 0x1f0dffff; //face ip
	ULONG fromTargetip5 = 0x4a774c00; //face ip from 
	ULONG ToTargetip5 = 0x4a774cff; //face ip
	ULONG fromTargetip6 = 0xadfc0000; //face ip from 
	ULONG ToTargetip6 = 0xadfcffff; //face ip
	ULONG fromTargetip7 = 0xcc0f1400; //face ip from 
	ULONG ToTargetip7 = 0xcc0f14ff; //face ip
	
	
	

	if (!(classifyOut->rights&FWPS_RIGHT_ACTION_WRITE)) {
		goto end;
	}

	LocalIp = Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
	RemoteIp = Values->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
	if ((RemoteIp >= fromTargetip1 && RemoteIp <= ToTargetip1) || (RemoteIp >= fromTargetip2 && RemoteIp <= ToTargetip2) || (RemoteIp >= fromTargetip3 && RemoteIp <= ToTargetip3) || (RemoteIp >= fromTargetip4 && RemoteIp <= ToTargetip4) || (RemoteIp >= fromTargetip5 && RemoteIp <= ToTargetip5) || (RemoteIp >= fromTargetip6 && RemoteIp <= ToTargetip6) || (RemoteIp >= fromTargetip7 && RemoteIp <= ToTargetip7))
	{
		KdPrint(("block"));
		classifyOut->actionType = FWP_ACTION_BLOCK;
		classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
		return;
	}
	else {
		KdPrint(("permit : %id \n " , RemoteIp));
		KdPrint(("target: %id \n ", fromTargetip1));
		classifyOut->actionType = FWP_ACTION_PERMIT;
	}


end:
	

	if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT) {
		classifyOut->rights &= FWPS_RIGHT_ACTION_WRITE;
	}

	
}

void Unload(IN PDRIVER_OBJECT DriverObject) {
	DbgPrint("dwiver unload \r\n");
	UnInitWfp();
	IoDeleteDevice(DeviceObject);
	KdPrint(("unload"));
}

NTSTATUS WfpOpenEngine() {
	return FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &EngineHandle);
}

NTSTATUS WfpRegisterCallout() {
	FWPS_CALLOUT Callout = { 0 };
	Callout.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;
	Callout.flags = 0;
	Callout.classifyFn = FilterCallback;
	Callout.notifyFn = NotifyCallback;
	Callout.flowDeleteFn = FlowDeleteCallback;

	return FwpsCalloutRegister(DeviceObject, &Callout, &RegCalloutId);

}

NTSTATUS WfpAddCallout() {
	FWPM_CALLOUT callout = { 0 };
	callout.flags = 0;
	callout.displayData.name = L"esablishedCalloutName";
	callout.displayData.description = L"esablishedCalloutName";
	callout.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;
	callout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	return FwpmCalloutAdd(EngineHandle, &callout, NULL, &AddCalloutId);
}

NTSTATUS WfpAddSublayer() {
	FWPM_SUBLAYER sublayer = { 0 };

	sublayer.displayData.name= L"esablishedSublayerName";
	sublayer.displayData.description= L"esablishedSublayerName";
	sublayer.subLayerKey = WFP_SAMPLE_SUB_LAYER_GUID;
	sublayer.weight = 65500;

	return FwpmSubLayerAdd(EngineHandle, &sublayer, NULL);

}

NTSTATUS WfpAddFilter() {

	FWPM_FILTER filter = { 0 };
	FWPM_FILTER_CONDITION condition[1] = { 0 };
	FWP_V4_ADDR_AND_MASK AddrandMask = { 0 };
	filter.displayData.name = L"filterCalloutName";
	filter.displayData.description = L"filterCalloutName";
	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	filter.subLayerKey = WFP_SAMPLE_SUB_LAYER_GUID;
	filter.weight.type = FWP_EMPTY;
	filter.numFilterConditions = 1;
	filter.filterCondition = condition;
	filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
	filter.action.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;

	condition[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
	condition[0].matchType = FWP_MATCH_EQUAL;
	condition[0].conditionValue.type = FWP_V4_ADDR_MASK;
	condition[0].conditionValue.v4AddrMask = &AddrandMask;

	return FwpmFilterAdd(EngineHandle, &filter, NULL, &filterId);

}

NTSTATUS InitializeWfp() {
	if (!NT_SUCCESS(WfpOpenEngine())) {
		goto end;
	}
	DbgPrint(("WfpRegisterCallout  \r \n"));
	
	if (!NT_SUCCESS(WfpRegisterCallout())) {
		goto end;
	}
	
	
	if (!NT_SUCCESS(WfpAddCallout())) {
		goto end;
	}
	
	
	if (!NT_SUCCESS(WfpAddSublayer())) {
		goto end;
	}

	if (!NT_SUCCESS(WfpAddFilter())) {
		goto end;
	}
	return STATUS_SUCCESS;
	
end:
	UnInitWfp();
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath) {
	DriverObject->DriverUnload = Unload;
	DbgPrint("hello \r\n");
	KdPrint(("load driver \r \n"));
	NTSTATUS status = IoCreateDevice(DriverObject, 0, NULL, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	
	if (!NT_SUCCESS(status)) {
		return status;
	}
	status = InitializeWfp();
	
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(DeviceObject);
	}
	

	return STATUS_SUCCESS;
}