class FitnessApp {
    constructor() {
        this.apiUrl = 'http://localhost:8000';
        this.token = localStorage.getItem('token');
    }

    // Регистрация
    async function register(email, password) {
    const response = await fetch('http://localhost:8000/register', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({email, password})
    });
    return response.json();
    }

    // Вход
    async login(email, password) {
        const response = await fetch(`${this.apiUrl}/token`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({email, password})
        });
        const data = await response.json();
        if(data.access_token) {
            localStorage.setItem('token', data.access_token);
            this.token = data.access_token;
        }
        return data;
    }

    // Создание тренировки
    async createWorkout(date, exercises) {
        const response = await fetch(`${this.apiUrl}/workouts`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.token}`
            },
            body: JSON.stringify({date, exercises})
        });
        return response.json();
    }

    // Таймер
    createTimer(duration, elementId) {
        let time = duration;
        const timerElement = document.getElementById(elementId);
        
        const interval = setInterval(() => {
            const minutes = Math.floor(time / 60);
            const seconds = time % 60;
            
            timerElement.textContent = 
                `${minutes}:${seconds.toString().padStart(2, '0')}`;
            
            if(--time < 0) {
                clearInterval(interval);
                timerElement.textContent = "Время вышло!";
            }
        }, 1000);
    }
}