let locale;
let configuration
document.addEventListener("DOMContentLoaded", () => {
  setLocale();
});
async function setLocale() {
  let configurationResp = await fetch(`/pbsworks/data/pa/locale/en_US.json`);
  configuration = await configurationResp.json();
  let newLocale = configuration.locale.default;
  applyBranding(configuration.branding);
  if (newLocale === locale) return;
  const newTranslations =
    await fetchTranslationsFor(newLocale);
  locale = newLocale;
  translations = newTranslations;
  translatePage();
}
async function fetchTranslationsFor(newLocale) {
  const response = await fetch(`/pbsworks${configuration.locale.availableLocales[configuration.locale.default]}`);
  return await response.json();
}
function translatePage() {
  document
    .querySelectorAll("[data-i18n-key]")
    .forEach(translateElement);
};
function translateElement(element) {
  const key = element.getAttribute("data-i18n-key");
  const value = element.getAttribute(key);
  const translation = translations[value] ? translations[value] : value;
  element.setAttribute(key, translation);
}
function applyBranding(branding) {
  if (branding.appLogo) {
    document.getElementById("app-logo-img").setAttribute("src", branding.appLogo);
    document.getElementById("app-logo").style.visibility = 'visible';
  }
  if (branding.appDescription) {
    document.getElementById("app-descirption").innerText = branding.appDescription;
    document.getElementById("app-descirption").style.visibility = 'visible';
  }
}
