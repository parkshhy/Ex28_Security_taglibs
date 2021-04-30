import React, { Component } from 'react';
import { Grid, Cell, List, ListItem, ListItemContent } from 'react-mdl';


class Contact extends Component {
    render() {
        return (
            <div className="contact-body">
                <Grid className="contact-grid">
                    <Cell col={6}>
                        <img
                            
                            alt="avater"
                            style={{ height: '350px' }}
                            />
                        <p style={{ width: '75%', margin: 'auto', padding: '1em' }}>
                         
                           <br/>
                         
                            <h2>박 상 현</h2>
                         </p>
                    </Cell>
                    <Cell col={6}>
                        <h2>Contact Me</h2>
                        <hr />
                        <div className="contact-list">
                            <List>
                                <ListItem style={{marginTop:50}}>
                                    <ListItemContent icon="person" style={{fontSize:'30px',marginLeft:150}}> 
                                    010-2197-1370</ListItemContent>
                                </ListItem>
                                <ListItem>
                                    <ListItemContent icon="person" style={{fontSize:'30px',marginLeft:150}}> 
                                    rainbluebird8@gmail.com</ListItemContent>
                                </ListItem>
                            </List>
                        </div>
                    </Cell>
                </Grid>
            </div>
        )
    }
}
export default Contact;