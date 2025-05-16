import requests
from typing import Dict, List, Any # Добавил List, Any
from datetime import datetime
import json # json нужен только для примера в main

def _get_cookie_security_recommendations(cookie_attributes: Dict[str, Any]) -> List[str]:
    """
    Генерирует рекомендации по безопасности для одной cookie.
    """
    recommendations = []
    if not cookie_attributes.get('secure'):
        recommendations.append('Установить флаг Secure')
    if not cookie_attributes.get('httponly'):
        recommendations.append('Установить флаг HttpOnly')
    if not cookie_attributes.get('samesite_value'): # Проверяем наличие значения SameSite
        recommendations.append('Установить атрибут SameSite (рекомендуемые значения: "Strict" или "Lax")')
    # Можно добавить другие проверки, например, на отсутствие 'Path=/' или 'Domain'
    # или на слишком большой срок 'Max-Age'/'Expires'
    return recommendations

def scan_cookies(url: str) -> Dict:
    """
    Сканирует cookie с указанного URL, анализирует их атрибуты безопасности
    и записывает отчет в doc.txt.

    Args:
        url (str): URL для сканирования cookie.

    Returns:
        Dict: Словарь, содержащий результаты анализа cookie или ошибку.
    """
    results: Dict[str, Any] = { # Уточнил тип для results
        'url': url,
        'scan_time': datetime.now().isoformat(),
        'cookies_found': 0,
        'cookie_details': [],
        'security_recommendations': set() # Используем set для автоматической дедупликации
    }
    try:
        # Отправляем GET запрос на указанный URL
        # Добавляем User-Agent, чтобы выглядеть как обычный браузер,
        # некоторые сайты могут не отдавать куки без него.
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, timeout=10, headers=headers) # Добавлен timeout и headers
        response.raise_for_status() # Проверка на HTTP ошибки (4xx, 5xx)

        # Получаем все cookie из ответа
        cookies = response.cookies # Это RequestsCookieJar

        results['cookies_found'] = len(cookies)

        # Анализируем каждую cookie
        for cookie in cookies: # cookie здесь это requests.cookies.Cookie
            samesite_val = cookie._rest.get('SameSite', cookie._rest.get('samesite'))

            cookie_info = {
                'name': cookie.name,
                'value': cookie.value, # Для отчета значение может быть важно, но для безопасности - нет
                'domain': cookie.domain,
                'path': cookie.path,
                'secure': cookie.secure,
                'httponly': 'HttpOnly' in cookie._rest or 'httponly' in cookie._rest,
                'samesite_value': samesite_val, # 'Lax', 'Strict', 'None' или None если не установлен
                'expires': datetime.fromtimestamp(cookie.expires).isoformat() if cookie.expires else None,
                # Другие потенциально интересные атрибуты из cookie._rest:
                # 'Max-Age': cookie._rest.get('Max-Age'),
            }

            recommendations = _get_cookie_security_recommendations(cookie_info)
            cookie_info['recommendations'] = recommendations
            results['cookie_details'].append(cookie_info)

            if recommendations:
                for rec in recommendations:
                    results['security_recommendations'].add(rec) # Добавляем в set

        # Конвертируем set обратно в list для JSON-совместимости и последовательного вывода
        results['security_recommendations'] = sorted(list(results['security_recommendations']))

        # Записываем результаты в файл doc.txt
        # Доказательством выполнения запроса является сам факт наличия данных о куки для этого URL
        # и указание URL и времени сканирования в отчете.
        with open('doc.txt', 'w', encoding='utf-8') as f:
            f.write(f"Результаты сканирования cookie для URL: {url}\n")
            f.write(f"Время сканирования: {results['scan_time']}\n")
            f.write(f"HTTP Status Code ответа: {response.status_code}\n") # Дополнительное доказательство
            f.write(f"Всего найдено cookie: {results['cookies_found']}\n\n")

            if not results['cookie_details']:
                f.write("Cookies не найдены или сервер их не установил.\n")

            for idx, cookie_detail in enumerate(results['cookie_details']):
                f.write(f"--- Cookie #{idx + 1} ---\n")
                f.write(f"Имя: {cookie_detail['name']}\n")
                # f.write(f"Значение: {cookie_detail['value']}\n") # Раскомментировать при необходимости
                f.write(f"Домен: {cookie_detail['domain']}\n")
                f.write(f"Путь: {cookie_detail['path']}\n")
                f.write(f"Атрибут Secure: {cookie_detail['secure']}\n")
                f.write(f"Атрибут HttpOnly: {cookie_detail['httponly']}\n")
                f.write(f"Атрибут SameSite: {cookie_detail['samesite_value'] if cookie_detail['samesite_value'] else 'Не установлен'}\n")
                f.write(f"Истекает (Expires/Max-Age): {cookie_detail['expires'] if cookie_detail['expires'] else 'Сессионная (или не указано)'}\n")

                if cookie_detail['recommendations']:
                    f.write("Рекомендации по улучшению безопасности:\n")
                    for rec in cookie_detail['recommendations']:
                        f.write(f"  - {rec}\n")
                f.write("\n")

            if results['security_recommendations']:
                f.write("\n--- Общие рекомендации по безопасности для сайта ---\n")
                for rec in results['security_recommendations']:
                    f.write(f"- {rec}\n")
            else:
                f.write("\n--- Общие рекомендации по безопасности для сайта ---\n")
                f.write("Для проанализированных cookie не найдено очевидных упущений в базовых флагах безопасности (Secure, HttpOnly, SameSite).\n")
        return results

    except requests.exceptions.RequestException as e: # Более конкретное исключение
        error_info = {
            'error': f"Ошибка при запросе к URL: {str(e)}",
            'url': url,
            'scan_time': datetime.now().isoformat()
        }
        # Попытка записать ошибку в doc.txt тоже
        try:
            with open('doc.txt', 'w', encoding='utf-8') as f:
                f.write(f"Ошибка сканирования для URL: {url}\n")
                f.write(f"Время: {error_info['scan_time']}\n")
                f.write(f"Ошибка: {error_info['error']}\n")
        except Exception as write_e:
            # Если даже запись файла не удалась, просто выводим в консоль
            print(f"Критическая ошибка при записи лога: {write_e}")
        return error_info
    except Exception as e: # Общее исключение для других непредвиденных ошибок
        # Это должно быть последним блоком except
        return {
            'error': f"Непредвиденная ошибка: {str(e)}",
            'url': url,
            'scan_time': datetime.now().isoformat()
        }


if __name__ == "__main__":
    # Тестовый URL для проверки работы скрипта
    # test_url = "https://google.com" # google.com перенаправляет на www.google.com, который может иметь другие куки
    test_url = "https://google.com"
    # test_url = "https://northeastern.edu" # Пример сайта с разными куками
    # test_url = "https://expired.badssl.com/" # Пример сайта с ошибкой SSL
    # test_url = "http://httpstat.us/500" # Пример ошибки сервера

    print(f"Сканирование URL: {test_url}")
    results = scan_cookies(test_url)

    # Вывод результатов в консоль в формате JSON для наглядности
    print("\nРезультат выполнения функции (JSON):")
    print(json.dumps(results, indent=4, ensure_ascii=False))

    print(f"\nПодробный отчет сохранен в файле: doc.txt")

    # Создание requirements.txt
    with open('requirements.txt', 'w') as req_file:
        req_file.write('requests\n')
    print("Файл requirements.txt создан/обновлен.")