#include <godot_cpp/godot.hpp>

using namespace godot;

extern "C" GDExtensionBool GDE_EXPORT smoke_library_init(
        GDExtensionInterfaceGetProcAddress get_proc_address,
        GDExtensionClassLibraryPtr library,
        GDExtensionInitialization *initialization) {
    GDExtensionBinding::InitObject init(get_proc_address, library, initialization);
    return init.init();
}
