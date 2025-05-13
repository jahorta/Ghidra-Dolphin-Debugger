/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package dolphindebugger;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = "Dolphin GDB Debugger",
    category = PluginCategoryNames.DEBUGGER,
    shortDescription = "Debugger for Dolphin GDB stub",
    description = "Connects to and manages debugging sessions to the Dolphin GDB stub using the devkitPPC version of GDB."
)
public class DolphinDebuggerPlugin extends ProgramPlugin {

    private DolphinComponentProvider provider;

    public DolphinDebuggerPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "DolphinGDB Debugger Plugin initialized");

        String pluginName = getName();
        provider = new DolphinComponentProvider(this.getTool(), pluginName, pluginName);

        String topicName = this.getClass().getPackage().getName();
        String anchorName = "HelpAnchor";
        provider.setHelpLocation(new HelpLocation(topicName, anchorName));
    }
    
    @Override
    protected void programClosed(Program program) {
        if (provider != null) {
        	provider.saveAndCloseTrace();
        	provider.saveCommandHistoryToFile();
        }
    }

    
}