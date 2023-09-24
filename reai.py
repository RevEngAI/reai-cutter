import cutter
from reait import api

from PySide2.QtCore import Qt
from PySide2.QtWidgets import QVBoxLayout, QLabel, QWidget, QSizePolicy, QPushButton

class FortuneWidget(cutter.CutterDockWidget):
	def __init__(self, parent):
		super(FortuneWidget, self).__init__(parent)
		self.setObjectName("FancyDockWidgetFromCoolPlugin")
		self.setWindowTitle("REAI Plugin")

		content = QWidget()
		self.setWidget(content)

		# Create layout and label
		layout = QVBoxLayout(content)
		content.setLayout(layout)
		self.text = QLabel(content)
		self.text.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
		self.text.setFont(cutter.Configuration.instance().getFont())
		layout.addWidget(self.text)

		button = QPushButton(content)
		button.setText("Want a fortune?")
		button.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum)
		button.setMaximumHeight(50)
		button.setMaximumWidth(200)
		layout.addWidget(button)
		layout.setAlignment(button, Qt.AlignHCenter)

		button.clicked.connect(self.generate_fortune)
		cutter.core().seekChanged.connect(self.generate_fortune)

		self.show()

	def generate_fortune(self):
		fortune = cutter.cmd("fortune").replace("\n", "")
		res = cutter.core().cmdRaw(f"?E {fortune}")
		self.text.setText(res)





class REAIPlugin(cutter.CutterPlugin):
	name = "reai"
	description = "RevEng.AI Cutter Plugin."
	version = "0.0.1"
	author = "James Patrick-Evans"

	# Override CutterPlugin methods

	def __init__(self):
		super(REAIPlugin, self).__init__()
		self.disassembly_actions = []
		self.addressable_item_actions = []
		self.disas_action = None
		self.addr_submenu = None
		self.main = None
		self.fpath = None

	def setupPlugin(self):
		pass

	def setupInterface(self, main):
		# Dock widget
		widget = FortuneWidget(main)
		main.addPluginDockWidget(widget)

		# Dissassembly context menu
		menu = main.getContextMenuExtensions(cutter.MainWindow.ContextMenuType.Disassembly)
		self.disas_action = menu.addAction("REAI Identify Function")
		self.disas_action.triggered.connect(self.handle_identify_function_action)
		self.main = main

		# Context menu for tables with addressable items like Flags,Functions,Strings,Search results,...
		addressable_item_menu = main.getContextMenuExtensions(cutter.MainWindow.ContextMenuType.Addressable)
		self.addr_submenu = addressable_item_menu.addMenu("REAIPlugin") # create submenu
		adrr_action = self.addr_submenu.addAction("Action 1")
		self.addr_submenu.addSeparator() # can use separator and other qt functionality
		adrr_action2 = self.addr_submenu.addAction("Action 2")
		adrr_action.triggered.connect(self.handle_addressable_item_action)
		adrr_action2.triggered.connect(self.handle_addressable_item_action)


	def terminate(self): # optional
		print("REAIPlugin shutting down")
		if self.main:
			menu = self.main.getContextMenuExtensions(cutter.MainWindow.ContextMenuType.Disassembly)
			menu.removeAction(self.disas_action)
			addressable_item_menu = self.main.getContextMenuExtensions(cutter.MainWindow.ContextMenuType.Addressable)
			submenu_action = self.addr_submenu.menuAction()
			addressable_item_menu.removeAction(submenu_action)
		print("REAIPlugin finished clean up")

	# Plugin methods

	def handle_addressable_item_action(self):
		# for actions in plugin menu Cutter sets data to current item address
		submenu_action = self.addr_submenu.menuAction()
		cutter.message("Context menu action callback 0x{:x}".format(submenu_action.data()))

	def handle_identify_function_action(self):
		# for actions in plugin menu Cutter sets data to address for current dissasembly line
		cutter.message("Dissasembly menu action callback 0x{:x}".format(self.disas_action.data()))
		print(type(self.disas_action))
		vaddr = int(self.disas_action.data())
		print(f"Using vaddr {vaddr}")

		#get function boundaries
		funcs = list(filter(lambda x: x['from'] >= vaddr and x['to'] >= vaddr, cutter.cmdj("aflj")))
		if len(funcs) == 0:
			print("Cutter error, can't find function")

		func = funcs[0]
		api.RE_embedding(self.binary_id(), start_vaddr, end_vaddr, base_vaddr=base)


	@staticmethod
	def binary_path():
		"""
		Return path to opened binary file
		"""
		opened_file = list(filter(lambda x: x['fd'] == 3, cutter.cmdj('olj')))
		if len(opened_file) == 0:
			raise RuntimeError("Cannot determine file path of binary to analyse")

		fpath = opened_file['uri']
		return fpath


	def analyse(self):
		"""
		Analyze currently open binary
		e.g. aR
		"""
		fpath = REAIPlugin.binary_path()
		return api.RE_analyse(fpath)


	def delete(self):
		fpath = REAIPlugin.binary_path()
		return api.RE_delete(fpath)


	def nearest_symbols(command):
		"""
		Get function name suggestions for each function
		"""
		f_suggestions = api.RE_nearest_symbols(embedding, 5, collections)
		# apply names using comments

		# add all name suggestions with probabilities as comments
		for vaddr, suggestion in f_suggestions.items():
				name, prob = suggestion
				cutter.cmd(f"CC '{name} - {prob}' @{vaddr}")

		# rename function most confident name
		#cutter.cmd(f"afn best_name @fnc.func0000000")




# This function will be called by Cutter and should return an instance of the plugin.
def create_cutter_plugin():
	return REAIPlugin()
