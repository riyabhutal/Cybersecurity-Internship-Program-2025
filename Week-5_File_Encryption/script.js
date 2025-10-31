document.getElementById('encryptForm').addEventListener('submit', async (e) => {
  e.preventDefault();

  const file = document.getElementById('file').files[0];
  const password = document.getElementById('password').value;

  const formData = new FormData();
  formData.append('file', file);
  formData.append('password', password);

  const response = await fetch('http://127.0.0.1:5000/encrypt', {
    method: 'POST',
    body: formData,
  });

  const blob = await response.blob();
  const link = document.createElement('a');
  link.href = window.URL.createObjectURL(blob);
  link.download = 'encrypted_file.txt';
  link.click();
});