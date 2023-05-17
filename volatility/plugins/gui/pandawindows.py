# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (C) 2010,2011,2012 Michael Hale Ligh <michael.ligh@mnin.org>
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

import volatility.plugins.gui.windowstations as windowstations
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address, Hex

class PandaWindows():
    def __init__(self, config, *args, **kwargs):
        #super(PandaWindows, self).__init__(config, args, kwargs)
        self._config = config
        self.main_desktop = None

    def get_desktop_wins(self, d):
        windows = []
        win = d.DeskInfo.spwnd
        for w, level in d.windows(win=win, fltr=lambda x: 'WS_VISIBLE' in str(x.style)):
            windows.append(w)
        return windows

    def calculate(self):
        data = windowstations.WndScan(self._config).calculate()
        if self.main_desktop:
            return self.get_desktop_wins(main_desktop)
        ret = []
        for window_station in data:
            for desktop in window_station.desktops():
                windows = self.get_desktop_wins(desktop)
                if any(w.rcWindow.left != 0 for w in windows):
                    self.main_desktop = desktop
                    return windows
        
    
