

def setTabs(self):

    disabledTabs = self._settings.global_get(["appearance", "components", "disabled", "tab"])
    if disabledTabs is None:
        disabledTabs = []

    if self.hideTempTab:
        if "temperature" not in disabledTabs:
            disabledTabs.append("temperature")
    elif "temperature" in disabledTabs:
        disabledTabs.remove("temperature")

    if self.hideControlTab:
        if "control" not in disabledTabs:
            disabledTabs.append("control")
    elif "control" in disabledTabs:
        disabledTabs.remove("control")

    if self.hideGCodeTab:
        if "gcodeviewer" not in disabledTabs:
            disabledTabs.append("gcodeviewer")
    elif "gcodeviewer" in disabledTabs:
        disabledTabs.remove("gcodeviewer")

    self._settings.global_set(["appearance", "components", "disabled", "tab"], disabledTabs)
