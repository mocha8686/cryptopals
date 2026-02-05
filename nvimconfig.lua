local function docServer()
	local toggleterm = require("toggleterm")
	toggleterm.exec("bacon doc", 1)
	toggleterm.exec("cd target/doc && python3 -m http.server", 2)
	toggleterm.toggle(2)
	toggleterm.toggle(3)
end

vim.keymap.set("n", "<leader>tk", docServer, { noremap = true, silent = true, desc = "Start doc server" })
