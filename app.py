import datetime
from flask import Flask, redirect, request, jsonify, render_template, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
import pickle
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix
import matplotlib.pyplot as plt
import base64
from io import BytesIO
from sklearn.metrics import roc_auc_score
import features as fe
from bs4 import BeautifulSoup
import requests

# Create the Flask app
app = Flask(__name__)
app.secret_key = 'xyzsdfg'

# MySQL configuration
app.config['MYSQL_HOST'] = '127.0.0.1'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'users'

mysql = MySQL(app)

# Function to perform the prediction
def predict_attack(data, selected_algorithm):
    model = pickle.load(open(selected_algorithm, "rb"))
    prediction = model.predict(data)
    return prediction

# Login route
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'loggedin' in session:
        return redirect(url_for('user'))

    message = ''
    if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
        email = request.form['email']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user WHERE email = %s AND password = %s', (email, password))
        user = cursor.fetchone()
        if user:
            session['loggedin'] = True
            session['userid'] = user['userid']
            session['name'] = user['name']
            session['email'] = user['email']
            message = 'Inscrit avec succès !'
            return redirect(url_for('user'))
        else:
            message = 'Veuillez entrer e-mail/mot de passe correct !'
    return render_template('login.html', message=message)

# Logout route
@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('userid', None)
    session.pop('email', None)
    session.pop('name', None)
    return redirect(url_for('login'))

# User route
@app.route('/user')
def user():
    if 'loggedin' in session:
        return render_template('user.html', name=session['name'])
    return redirect(url_for('login'))

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    message = ''
    if request.method == 'POST' and 'name' in request.form and 'password' in request.form and 'email' in request.form:
        userName = request.form['name']
        password = request.form['password']
        email = request.form['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user WHERE email = %s', (email,))
        account = cursor.fetchone()
        if account:
            message = 'Le compte existe déjà!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            message = 'Adresse email invalide !'
        elif not userName or not password or not email:
            message = 'Veuillez remplir le formulaire !'
        else:
            cursor.execute('INSERT INTO user VALUES (NULL, %s, %s, %s)', (userName, email, password))
            mysql.connection.commit()
            message = 'Vous vous êtes inscrit avec succès !'
    elif request.method == 'POST':
        message = 'Veuillez remplir le formulaire !'
    return render_template('register.html', message=message)

# About route
@app.route('/about')
def about():
    return render_template('about.html')

# Home route
@app.route('/home')
def home():
    return render_template('user.html')

@app.route('/predict', methods=['GET', 'POST'])
def predict():
    if 'loggedin' in session:
        if request.method == 'POST':
            selected_algorithm = request.form['algorithm']
            float_features = [float(X) for name, X in request.form.items() if name != 'algorithm']
            features = np.array(float_features).reshape(1, -1)
            prediction = predict_attack(features, selected_algorithm)
            attack_status = "Aucune attaque détectée." if prediction == 0 else "Attaque détectée."
            float_features.append(selected_algorithm)
            float_features.append(attack_status)
            
            try:
                cursor = mysql.connection.cursor()
                cursor.execute('''
                    INSERT INTO historyForm (rate, sttl, state, dload, swin, ackdat, ct_src_ltm, proto, dmean, ct_dst_ltm, dur, service, dwin, ct_state_ttl, ct_src_dport_ltm, ct_dst_sport_ltm, ct_srv_src, ct_dst_src_ltm, ct_srv_dst, algorithm, attack_status, created_at) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                    ''', float_features)
                mysql.connection.commit()
                cursor.close()
            except Exception as e:
                print("An error occurred while inserting prediction results into the database:", str(e))

            return render_template("pre.html", prediction_text=attack_status, algorithm=selected_algorithm)

        return render_template("index.html")
    else:
        return redirect(url_for('login'))

@app.route('/prediction_form_results')
def prediction_form_results():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM historyForm ORDER BY created_at DESC')
        prediction_results = cursor.fetchall()
        cursor.close()
        return render_template('prediction_form_results.html', prediction_results=prediction_results)
    else:
        return redirect(url_for('login'))

@app.route('/delete_prediction_form/<int:prediction_id>', methods=['POST'])
def delete_prediction_form(prediction_id):
    if 'loggedin' in session:
        try:
            cursor = mysql.connection.cursor()
            cursor.execute('DELETE FROM historyForm WHERE id = %s', (prediction_id,))
            mysql.connection.commit()
            cursor.close()
            return redirect(url_for('prediction_form_results'))
        except Exception as e:
            return render_template('error.html', message=str(e))
    else:
        return redirect(url_for('login'))

@app.route('/prediction_results')
def prediction_results():
    cursor = mysql.connection.cursor()
    cursor.execute('SELECT * FROM user JOIN prediction_results ON user.userid = prediction_results.user_id')
    prediction_results = cursor.fetchall()
    cursor.close()
    return render_template('prediction_results.html', prediction_results=prediction_results)

@app.route('/delete_prediction/<int:prediction_id>', methods=['POST'])
def delete_prediction(prediction_id):
    try:
        cursor = mysql.connection.cursor()
        cursor.execute('DELETE FROM prediction_results WHERE id = %s', (prediction_id,))
        mysql.connection.commit()
        cursor.close()
        return redirect(url_for('prediction_results'))
    except Exception as e:
        return render_template('error.html', message=str(e))

# Prediction form route
@app.route('/URMOM')
def formulaire():
    return render_template("formulaire.html")

models = {
    "XGBClassifier.pkl": pickle.load(open("XGBClassifier.pkl", "rb")),
    "DecisionTreeClassifier.pkl": pickle.load(open("DecisionTreeClassifier.pkl", "rb")),
    "LogisticRegression.pkl": pickle.load(open("LogisticRegression.pkl", "rb")),
    "RandomForestClassifier.pkl": pickle.load(open("RandomForestClassifier.pkl", "rb")),
    "SVM.pkl": pickle.load(open("SVM.pkl", "rb"))
}

@app.route('/predictiongg', methods=['POST'])
def predictiongg():
    file = request.files['file']
    if not (file.filename.endswith('.xlsx') or file.filename.endswith('.csv')):
        return render_template('error.html', message="Le fichier doit être au format .xlsx ou .csv.")

    try:
        df = pd.read_excel(file, header=None) if file.filename.endswith('.xlsx') else pd.read_csv(file, header=None)
    except Exception as e:
        return render_template('error.html', message=str(e))

    if len(df.columns) != 19:
        message = "Le fichier doit contenir exactement 19 colonnes."
        return render_template('error.html', message=message)

    df = df.apply(pd.to_numeric, errors='coerce').dropna()
    if df.empty:
        return render_template('error.html', message="Toutes les lignes du fichier contiennent des valeurs non numériques.")

    selected_algorithm = request.form['algorithm']
    user_id = session.get('userid')
    file_name = file.filename

    results = []
    for index, row in df.iterrows():
        row_data = np.array(row.values).reshape(1, -1)
        prediction = predict_attack(row_data, selected_algorithm)
        attack_status = "Attaque détectée." if prediction[0] == 1 else "Aucune attaque détectée."
        results.append({'ID': index + 1, 'attack_status': attack_status})

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('INSERT INTO prediction_results (user_id, file_name, attack_status) VALUES (%s, %s, %s)',
                       (user_id, file_name, attack_status))
        mysql.connection.commit()
        cursor.close()
 # Calculate the percentage of attacks detected and non-attacks detected
    num_attacks = sum(1 for result in results if result['attack_status'] == "Attaque détectée.")
    num_non_attacks = len(results) - num_attacks
    total_instances = len(results)
    attack_percentage = (num_attacks / total_instances) * 100
    non_attack_percentage = (num_non_attacks / total_instances) * 100

    # Pass these percentages to the result template
    return render_template("result.html", results=results,
                           attack_percentage=attack_percentage, non_attack_percentage=non_attack_percentage, algorithm=selected_algorithm)


def open_file(f_name):
    with open(f_name, "r") as f:
        return f.read()

def create_soup(text):
    return BeautifulSoup(text, "html.parser")

def create_vector(soup):
    return [
        fe.has_title(soup),
        fe.has_input(soup),
        fe.has_button(soup),
        fe.has_image(soup),
        fe.has_submit(soup),
        fe.has_link(soup),
        fe.has_password(soup),
        fe.has_email_input(soup),
        fe.has_hidden_element(soup),
        fe.has_audio(soup),
        fe.has_video(soup),
        fe.number_of_inputs(soup),
        fe.number_of_buttons(soup),
        fe.number_of_images(soup),
        fe.number_of_option(soup),
        fe.number_of_list(soup),
        fe.number_of_TH(soup),
        fe.number_of_TR(soup),
        fe.number_of_href(soup),
        fe.number_of_paragraph(soup),
        fe.number_of_script(soup),
        fe.length_of_title(soup),
        fe.has_h1(soup),
        fe.has_h2(soup),
        fe.has_h3(soup),
        fe.length_of_text(soup),
        fe.number_of_clickable_button(soup),
        fe.number_of_a(soup),
        fe.number_of_img(soup),
        fe.number_of_div(soup),
        fe.number_of_figure(soup),
        fe.has_footer(soup),
        fe.has_form(soup),
        fe.has_text_area(soup),
        fe.has_iframe(soup),
        fe.has_text_input(soup),
        fe.number_of_meta(soup),
        fe.has_nav(soup),
        fe.has_object(soup),
        fe.has_picture(soup),
        fe.number_of_sources(soup),
        fe.number_of_span(soup),
        fe.number_of_table(soup)
    ]

def predict (data, selected):
    # Load the selected model
    if selected == "XGBOSST.pkl":
        model = pickle.load(open("XGBOSST.pkl", "rb"))
    elif selected == "DecisionTree.pkl":
        model = pickle.load(open("DecisionTree.pkl", "rb"))
    elif selected == "LogisticReg.pkl":
        model = pickle.load(open("LogisticReg.pkl", "rb"))
    elif selected == "RandomForest.pkl":
        model = pickle.load(open("RandomForest.pkl", "rb"))
    elif selected == "SVC.pkl":
        model = pickle.load(open("SVC.pkl", "rb"))
    else:
        return "Modèle non trouvé."

    try:
        vector = [create_vector(data)]
        prediction = model.predict(vector)
        if prediction[0] == 1:
            return "Cette page Web semble légitime !"
        else:
            return "Attention! This web page is a potential PHISHING!"
    except Exception as e:
        print("An error occurred:", str(e))
        return None

def save_url_history(url, selected_algorithm, prediction, user_id):
    try:
        cursor = mysql.connection.cursor()
        current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute("INSERT INTO historyUrl (url, algorithm, prediction, user_id, created_at) VALUES (%s, %s, %s, %s, %s)",
                       (url, selected_algorithm, prediction, user_id, current_time))
        mysql.connection.commit()
        cursor.close()
    except Exception as e:
        print("An error occurred while saving the URL history:", str(e))

@app.route('/url_result')
def url_prediction_results():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('''
           SELECT * FROM historyUrl  JOIN user  ON historyUrl.user_id = user.userid
        ''')
        prediction_results = cursor.fetchall()
        cursor.close()

        return render_template('url_result.html', prediction_results=prediction_results)
    else:
        return redirect(url_for('login'))



@app.route('/URL', methods=['GET', 'POST'])
def URL():
    if 'loggedin' in session:
        if request.method == 'POST':
            selected = request.form['algorithm']
            url = request.form['URL']  # Extract the URL value from the form
            user_id = session['userid']

            try:
                response = requests.get(url, verify=False, timeout=4)
                if response.status_code != 200:
                    return "La connexion HTTP n'a pas réussi pour l'URL spécifiée."
                else:
                    soup = BeautifulSoup(response.content, "html.parser")
                    prediction = predict(soup, selected)

                    # Save the URL history to the database
                    save_url_history(url, selected, prediction, user_id)

                    return render_template("pred_url.html", prediction=prediction, algorithm=selected)
            except Exception as e:
                print("An error occurred:", str(e))
                return "Une erreur s'est produite lors du traitement de l'URL."

        # If the request method is GET, render the URL prediction form
        return render_template("url.html", url=request.args.get('url'))  # Pass the URL value to the template
    else:
        return redirect(url_for('login'))


@app.route('/delete_url_prediction/<int:prediction_id>', methods=['POST'])
def delete_url_prediction(prediction_id):
    if 'loggedin' in session:
        try:
            cursor = mysql.connection.cursor()
            cursor.execute('DELETE FROM historyUrl WHERE id = %s', (prediction_id,))
            mysql.connection.commit()
            cursor.close()
            return redirect(url_for('URL'))
        except Exception as e:
            print("An error occurred while deleting the URL prediction:", str(e))
            return render_template('error.html', message="An error occurred while deleting the URL prediction.")
    else:
        return redirect(url_for('login'))


# Back route
@app.route('/back', methods=['GET'])
def back():
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True) 
