mkdir -p "$MODPATH/zygisk"
api_level_arch_detect
[ ! -d "$MODPATH/libs/$ABI" ] && abort "! $ABI not supported"
ui_print "- Extract Zygisk module..."
cp -af "$MODPATH/libs/$ABI/libzygisk_module.so" "$MODPATH/zygisk/$ABI.so"
cp -af "$MODPATH/libs/$ABI32/libzygisk_module.so" "$MODPATH/zygisk/$ABI32.so"
rm -rf "$MODPATH/libs"
