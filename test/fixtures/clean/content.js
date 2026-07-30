const words = document.body.innerText.trim().split(/\s+/).length;
chrome.storage.local.set({ lastCount: words });
document.title = `${Math.ceil(words / 220)} min read`;
