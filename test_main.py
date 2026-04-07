import sys
import string
import types
import unittest
from unittest.mock import Mock, patch

requests_stub = types.SimpleNamespace(
    get=Mock(),
    Timeout=type("Timeout", (Exception,), {}),
    RequestException=type("RequestException", (Exception,), {}),
)
sys.modules.setdefault("requests", requests_stub)

import Main


class SecurePassTests(unittest.TestCase):
    def test_generar_contrasena_incluye_todos_los_tipos_seleccionados(self):
        contrasena = Main.generar_contrasena(12, True, True, True, True)

        self.assertEqual(len(contrasena), 12)
        self.assertTrue(any(c.isupper() for c in contrasena))
        self.assertTrue(any(c.islower() for c in contrasena))
        self.assertTrue(any(c.isdigit() for c in contrasena))
        self.assertTrue(any(c in string.punctuation for c in contrasena))

    def test_generar_contrasena_falla_si_no_hay_tipos(self):
        resultado = Main.generar_contrasena(12, False, False, False, False)
        self.assertIn("Error:", resultado)

    def test_generar_contrasena_falla_si_longitud_no_alcanza(self):
        resultado = Main.generar_contrasena(2, True, True, True, False)
        self.assertIn("Error:", resultado)

    def test_calcular_entropia_de_cadena_vacia(self):
        self.assertEqual(Main.calcular_entropia(""), 0)

    @patch("Main.requests.get")
    def test_verificar_contrasena_pwned_detecta_filtracion(self, mock_get):
        mock_get.return_value = Mock(
            status_code=200,
            text="1E4C9B93F3F0682250B6CF8331B7EE68FD8:100\nABC:1",
        )

        resultado = Main.verificar_contrasena_pwned("password")

        self.assertIn("Comprometida", resultado)

    @patch("Main.requests.get", side_effect=Main.requests.Timeout)
    def test_verificar_contrasena_pwned_maneja_timeout(self, mock_get):
        resultado = Main.verificar_contrasena_pwned("password")
        self.assertIn("Tiempo de espera agotado", resultado)

    @patch("Main.requests.get", side_effect=Main.requests.RequestException)
    def test_verificar_contrasena_pwned_maneja_error_de_red(self, mock_get):
        resultado = Main.verificar_contrasena_pwned("password")
        self.assertIn("No se pudo conectar", resultado)


if __name__ == "__main__":
    unittest.main()
