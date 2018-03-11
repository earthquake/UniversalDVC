// dllmain.h : Declaration of module class.

class CUDVCPluginModule : public ATL::CAtlDllModuleT< CUDVCPluginModule >
{
public :
	DECLARE_LIBID(LIBID_UDVCPluginLib)
	DECLARE_REGISTRY_APPID_RESOURCEID(IDR_UDVCPLUGIN, "{B8DC075B-7F8D-4B06-8733-7EB586CA06F0}")
};

extern class CUDVCPluginModule _AtlModule;
