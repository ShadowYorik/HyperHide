#pragma once
#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS HkDetourFunction(
	_In_ PVOID	 TargetFunction,
	_In_ PVOID	 Hook,
	_Out_ PVOID* OriginalTrampoline
);

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS HkRestoreFunction(
	_In_ PVOID	 HookedFunction,
	_In_ PVOID	 OriginalTrampoline
);

#ifdef __cplusplus
}
#endif