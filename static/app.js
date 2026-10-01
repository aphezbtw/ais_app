document.addEventListener("DOMContentLoaded", function () {
  // Автоотправка формы фильтра при смене select'а
  document.querySelectorAll("[data-autosubmit]").forEach(function (el) {
    el.addEventListener("change", function () {
      el.form.submit();
    });
  });

  // Клик по строке таблицы — переход к заявке
  document.querySelectorAll("tr[data-href]").forEach(function (row) {
    row.addEventListener("click", function (event) {
      if (event.target.closest("a, button, input, select") || window.getSelection().toString()) return;
      window.location = row.getAttribute("data-href");
    });
  });

  // Заполняем ширину полос отчёта из data-pct (доступно и без CSP-инлайна)
  document.querySelectorAll(".bar-fill[data-pct]").forEach(function (el) {
    el.style.width = el.getAttribute("data-pct") + "%";
  });
});

document.querySelectorAll("[data-template]").forEach(function (button) {
  button.addEventListener("click", function () {
    const subject = document.getElementById("subject");
    const description = document.getElementById("description");
    if ((subject.value.trim() || description.value.trim()) && !window.confirm("Заменить введённый текст выбранным примером?")) return;
    ["subject", "description", "category", "priority"].forEach(function (key) {
      document.getElementById(key).value = button.dataset[key];
    });
    document.getElementById("template-feedback").textContent = "Пример добавлен. Уточните детали перед отправкой.";
    subject.focus();
  });
});
