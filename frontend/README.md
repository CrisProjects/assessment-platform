<<<<<<< HEAD
# Assessment Platform

A responsive web application for creating and taking assessments, with support for multiple participants and detailed result tracking.

## Features

- Responsive design for mobile, tablet, and desktop
- User authentication and admin roles
- Create and manage assessments
- Track multiple participants
- Detailed statistics and results
- Auto-advance questions
- Progress saving
- Participant filtering

## Local Development

1. Clone the repository
2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables in `.env`:
```
SECRET_KEY=your-secret-key
DATABASE_URL=sqlite:///assessments.db
```

5. Initialize the database:
```bash
python migrate_db.py
```

6. Run the development server:
```bash
python app.py
```

## Deployment

The app is ready to deploy to Heroku or any other platform that supports Python web applications.

### Heroku Deployment

1. Install the Heroku CLI
2. Login to Heroku:
```bash
heroku login
```

3. Create a new Heroku app:
```bash
heroku create your-app-name
```

4. Set environment variables:
```bash
heroku config:set SECRET_KEY=your-secret-key
heroku config:set FLASK_APP=app.py
```

5. Deploy:
```bash
git push heroku main
```

6. Initialize the database:
```bash
heroku run python migrate_db.py
```

### Railway Deployment

1. Create a new project on Railway
2. Connect your GitHub repository
3. Add the following environment variables:
   - SECRET_KEY
   - DATABASE_URL (Railway will provide this)
4. Deploy the main branch

## Testing

Access the application at the deployed URL or locally at http://localhost:5000

Default admin credentials:
- Username: admin
- Password: admin123

## Mobile Testing

The application is optimized for:
- iOS Safari
- Android Chrome
- Tablet browsers
- Desktop browsers

## Support

For issues or questions, please open a GitHub issue.
=======
# React + Vite

This template provides a minimal setup to get React working in Vite with HMR and some ESLint rules.

Currently, two official plugins are available:

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react/README.md) uses [Babel](https://babeljs.io/) for Fast Refresh
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react-swc) uses [SWC](https://swc.rs/) for Fast Refresh
>>>>>>> c2c698b (Frontend listo para Vercel)
